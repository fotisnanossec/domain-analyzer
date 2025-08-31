import requests
import json
from .exceptions import ReportGenerationError

class LMStudioClient:
    """Client to communicate with the LM Studio API server."""
    def __init__(self, config):
        llm_config = config.get("llm", {})
        self.api_url = f"http://{llm_config.get('host')}/v1/chat/completions"
        self.model = llm_config.get("model", "mistral-nemo-instruct-2407")
        self.temperature = llm_config.get("temperature", 0.8)
        self.max_tokens = llm_config.get("max_tokens", 16384)
        self.timeout = llm_config.get("timeout", 4800)

    def generate_report(self, prompt):
        """Sends a prompt to the LLM and returns the generated response."""
        headers = {"Content-Type": "application/json"}
        
        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens
        }
        
        try:
            # The 'timeout' value from config.toml is now used here.
            response = requests.post(self.api_url, headers=headers, data=json.dumps(data), timeout=self.timeout)
            response.raise_for_status()
            
            result = response.json()
            report_content = result['choices'][0]['message']['content']
            return report_content
        except requests.exceptions.Timeout:
            raise ReportGenerationError("API request timed out. Please check your LLM server and try increasing the 'timeout' value in config.toml.")
        except requests.exceptions.ConnectionError:
            raise ReportGenerationError("Could not connect to the LM Studio API. Please check the host address and ensure the server is running.")
        except requests.exceptions.HTTPError as err:
            raise ReportGenerationError(f"HTTP error occurred: {err}")
        except Exception as e:
            raise ReportGenerationError(f"An unexpected error occurred during the API request: {e}")

