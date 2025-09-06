import logging
import json
import re
from threading import Event

from PyQt6.QtCore import QThread, pyqtSignal

# It's good practice to handle the case where 'requests' might not be installed.
try:
    import requests
except ImportError:
    requests = None

class FetchModelsThread(QThread):
    """A dedicated thread to fetch AI models from an endpoint."""
    models_fetched = pyqtSignal(list)
    models_error = pyqtSignal(str)

    def __init__(self, url, parent=None):
        super().__init__(parent)
        self.url = url

    def run(self):
        if not requests:
            self.models_error.emit("The 'requests' library is not installed. Please run 'pip install requests'.")
            return
        try:
            response = requests.get(self.url, timeout=5)
            response.raise_for_status()
            data = response.json()
            model_names = [model['name'] for model in data.get('models', [])]
            self.models_fetched.emit(model_names)
        except Exception as e:
            self.models_error.emit(str(e))

class TestAPIThread(QThread):
    """A dedicated thread to test an API connection."""
    success = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, provider, api_key, parent=None):
        super().__init__(parent)
        self.provider = provider
        self.api_key = api_key

    def run(self):
        if not requests:
            self.error.emit("The 'requests' library is not installed. Please run 'pip install requests'.")
            return
        try:
            if self.provider == "OpenAI":
                url = "https://api.openai.com/v1/models"
                headers = {"Authorization": f"Bearer {self.api_key}"}
                response = requests.get(url, headers=headers, timeout=10)
                response.raise_for_status()
                # Check if we got a list of models
                if "data" in response.json():
                    self.success.emit(f"Successfully connected to {self.provider} and authenticated.")
                else:
                    self.error.emit(f"Authentication with {self.provider} failed. The response was unexpected.")
            else:
                self.error.emit(f"Connection testing for {self.provider} is not yet implemented.")
        except Exception as e:
            self.error.emit(f"Failed to connect to {self.provider}: {e}")


class AIAnalysisThread(QThread):
    """
    A thread to run AI analysis requests in the background, supporting streaming.
    Emits signals for each chunk of the response, distinguishing between 'thinking'
    and 'answer' parts of the stream.
    """
    response_ready = pyqtSignal(str, bool, bool)
    error = pyqtSignal(str)

    def __init__(self, prompt, settings, cancellation_event, parent=None):
        super().__init__(parent)
        self.prompt = prompt
        self.settings = settings
        self.cancellation_event = cancellation_event

    def run(self):
        if not requests:
            self.error.emit("The 'requests' library is not installed. Please run 'pip install requests'.")
            return
        try:
            provider = self.settings.get("provider")
            endpoint = self.settings.get("endpoint")
            model = self.settings.get("model")
            api_key = self.settings.get("api_key")

            if not provider or not model or not endpoint:
                raise ValueError("AI provider, model, or endpoint is not configured.")

            headers = {"Content-Type": "application/json"}
            if api_key and provider == "OpenAI":
                headers["Authorization"] = f"Bearer {api_key}"

            # The special tags should be part of the prompt for models that support them.
            # This is a more robust way to guide the model's output format.
            tagged_prompt = f"Please provide your response in two parts. First, explain your thought process within <thinking></thinking> tags. Then, provide the final answer within <answer></answer> tags.\n\nUser query: {self.prompt}"

            payload = {
                "model": model,
                "messages": [{"role": "user", "content": tagged_prompt}],
                "stream": True
            }

            with requests.post(endpoint, headers=headers, json=payload, stream=True, timeout=60) as response:
                response.raise_for_status()

                # Simplified state management
                current_phase = None # Can be "thinking" or "answer"
                buffer = ""

                for line in response.iter_lines():
                    if self.cancellation_event.is_set():
                        logging.info("AI analysis thread cancelled by user.")
                        break

                    if not line:
                        continue

                    line = line.decode('utf-8')
                    if line.startswith('data:'):
                        line = line[5:].strip()

                    try:
                        data = json.loads(line)
                        chunk = data.get('message', {}).get('content', '') or \
                                (data.get('choices', [{}])[0].get('delta', {}).get('content', '')) or \
                                data.get('response', '')

                        if not chunk:
                            continue

                        buffer += chunk

                        # Process buffer for tags
                        while True:
                            if self.cancellation_event.is_set(): break

                            if current_phase is None:
                                if '<thinking>' in buffer:
                                    parts = buffer.split('<thinking>', 1)
                                    buffer = parts[1]
                                    current_phase = "thinking"
                                elif '<answer>' in buffer:
                                    parts = buffer.split('<answer>', 1)
                                    buffer = parts[1]
                                    current_phase = "answer"
                                else:
                                    break # Need more data

                            elif current_phase == "thinking":
                                if '</thinking>' in buffer:
                                    parts = buffer.split('</thinking>', 1)
                                    self.response_ready.emit(parts[0], True, False)
                                    buffer = parts[1]
                                    current_phase = None
                                else:
                                    self.response_ready.emit(buffer, True, False)
                                    buffer = ""
                                    break

                            elif current_phase == "answer":
                                if '</answer>' in buffer:
                                    parts = buffer.split('</answer>', 1)
                                    self.response_ready.emit(parts[0], False, True)
                                    buffer = parts[1]
                                    current_phase = None
                                else:
                                    self.response_ready.emit(buffer, False, True)
                                    buffer = ""
                                    break
                            else:
                                break

                    except json.JSONDecodeError:
                        logging.warning(f"Could not decode JSON from stream line: {line}")
                        continue

        except Exception as e:
            if not self.cancellation_event.is_set():
                error_message = f"Failed to get AI analysis: {e}"
                logging.error(error_message, exc_info=True)
                self.error.emit(error_message)

    def stop(self):
        """Signals the thread to stop."""
        self.cancellation_event.set()
