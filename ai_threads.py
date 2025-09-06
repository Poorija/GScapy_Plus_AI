import logging
import json
import re
from threading import Event

from PyQt6.QtCore import QThread, pyqtSignal


class FetchModelsThread(QThread):
    """A dedicated thread to fetch AI models from an endpoint."""
    models_fetched = pyqtSignal(list)
    models_error = pyqtSignal(str)

    def __init__(self, url, parent=None):
        super().__init__(parent)
        self.url = url

    def run(self):
        try:
            import requests
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
        try:
            import requests
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
    # Signal: (chunk, is_thinking, is_final_answer_chunk)
    response_ready = pyqtSignal(str, bool, bool)
    error = pyqtSignal(str)

    def __init__(self, prompt, settings, parent=None):
        super().__init__(parent)
        self.prompt = prompt
        self.settings = settings
        self.stop_event = Event()

    def run(self):
        try:
            import requests

            provider = self.settings.get("provider")
            endpoint = self.settings.get("endpoint")
            model = self.settings.get("model")
            api_key = self.settings.get("api_key")

            if not provider or not model or not endpoint:
                raise ValueError("AI provider, model, or endpoint is not configured.")

            headers = {"Content-Type": "application/json"}
            if api_key and provider == "OpenAI":
                headers["Authorization"] = f"Bearer {api_key}"

            payload = {
                "model": model,
                "messages": [{"role": "user", "content": self.prompt}],
                "stream": True
            }

            with requests.post(endpoint, headers=headers, json=payload, stream=True, timeout=60) as response:
                response.raise_for_status()

                for line in response.iter_lines():
                    if self.stop_event.is_set():
                        break
                    if not line:
                        continue

                    line_str = line.decode('utf-8')
                    if line_str.startswith('data:'):
                        line_str = line_str[5:].strip()

                    if not line_str:
                        continue

                    try:
                        data = json.loads(line_str)
                        chunk = data.get('message', {}).get('content', '') or \
                                (data.get('choices', [{}])[0].get('delta', {}).get('content', '')) or \
                                data.get('response', '')

                        if not chunk:
                            continue

                        # Determine the state for each chunk independently
                        is_thinking_chunk = '<thinking>' in chunk.lower()
                        is_answer_chunk = '<answer>' in chunk.lower()

                        # Clean the chunk of tags
                        cleaned_chunk = re.sub(r'<\/?(thinking|answer)>', '', chunk, flags=re.IGNORECASE)

                        # The logic in the GUI depends on the 'is_thinking' flag.
                        # A chunk is for the "thinking" widget only if it's marked as such AND not as an answer.
                        is_for_thinking_widget = is_thinking_chunk and not is_answer_chunk

                        if cleaned_chunk:
                            self.response_ready.emit(cleaned_chunk, is_for_thinking_widget, is_answer_chunk)

                    except json.JSONDecodeError:
                        logging.warning(f"Could not decode JSON from stream line: {line_str}")
                        continue

        except Exception as e:
            error_message = f"Failed to get AI analysis: {e}"
            logging.error(error_message, exc_info=True)
            self.error.emit(error_message)

    def stop(self):
        self.stop_event.set()
