import logging
import requests
import json
import re

def get_ai_settings(settings_file="ai_settings.json"):
    """
    Loads AI settings from the JSON file and returns a dictionary
    containing the active provider's details.
    This is a helper function to be used by the API.
    """
    try:
        if not os.path.exists(settings_file):
            raise FileNotFoundError("ai_settings.json not found.")

        with open(settings_file, 'r') as f:
            settings = json.load(f)

        active_provider_name = settings.get("active_provider")
        active_model_name = settings.get("active_model")

        if not active_provider_name or not active_model_name:
            raise ValueError("No active AI model selected in ai_settings.json.")

        provider_details = {}
        if active_provider_name == "local_ai":
            local_settings = settings.get("local_ai", {})
            provider_details = {
                "provider": "local_ai",
                "endpoint": local_settings.get("endpoint", "http://localhost:11434/api/chat"),
                "model": active_model_name,
                "api_key": None
            }
        else:
            online_settings = settings.get("online_ai", {})
            provider_data = online_settings.get(active_provider_name, {})
            api_key = provider_data.get("api_key")
            endpoint = ""
            if active_provider_name == "OpenAI":
                endpoint = "https://api.openai.com/v1/chat/completions"
            # Add other online providers here

            if not endpoint:
                 raise ValueError(f"Endpoint for '{active_provider_name}' is not defined.")

            provider_details = {
                "provider": active_provider_name,
                "endpoint": endpoint,
                "model": active_model_name,
                "api_key": api_key
            }

        return provider_details

    except Exception as e:
        logging.error(f"Error loading AI settings: {e}", exc_info=True)
        return None


def stream_ai_analysis(prompt: str, settings: dict):
    """
    Runs an AI analysis request and yields response chunks for streaming.

    Args:
        prompt: The user's prompt for the AI.
        settings: A dictionary containing the AI provider's details (endpoint, model, api_key).

    Yields:
        A string chunk of the AI's response.
    """
    try:
        provider = settings.get("provider")
        endpoint = settings.get("endpoint")
        model = settings.get("model")
        api_key = settings.get("api_key")

        if not all([provider, model, endpoint]):
            raise ValueError("AI provider, model, or endpoint is not configured.")

        headers = {"Content-Type": "application/json"}
        if api_key and provider == "OpenAI":
            headers["Authorization"] = f"Bearer {api_key}"

        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": True
        }

        with requests.post(endpoint, headers=headers, json=payload, stream=True, timeout=60) as response:
            response.raise_for_status()

            for line in response.iter_lines():
                if not line: continue
                line = line.decode('utf-8')
                if line.startswith('data:'):
                    line = line[5:].strip()

                try:
                    data = json.loads(line)
                    chunk = data.get('message', {}).get('content', '') or \
                            (data.get('choices', [{}])[0].get('delta', {}).get('content', '')) or \
                            data.get('response', '')

                    if chunk:
                        # Clean out thinking/answer tags for pure text stream
                        chunk = re.sub(r'<\/?(thinking|answer)>', '', chunk, flags=re.IGNORECASE)
                        yield chunk

                except json.JSONDecodeError:
                    logging.warning(f"Could not decode JSON from stream line: {line}")
                    continue

    except Exception as e:
        error_message = f"Failed to get AI analysis: {e}"
        logging.error(error_message, exc_info=True)
        yield f"\n\n**ERROR**: {error_message}"
