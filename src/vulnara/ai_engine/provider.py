import os
from typing import Optional
import httpx

from vulnara.core.exceptions import VulnaraError


class AIProviderError(VulnaraError):
    pass


class OpenRouterProvider:
    BASE_URL = "https://openrouter.ai/api/v1/chat/completions"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        # Load the model directly from the .env file
        self.model = model or os.getenv("AI_MODEL", "meta-llama/llama-3-8b-instruct")

        if not self.api_key:
            raise AIProviderError("OPENROUTER_API_KEY environment variable is not set.")

    def generate_completion(self, system_prompt: str, user_data: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "https://github.com/chanukasandun/vulnara",
            "X-Title": "Vulnara Framework",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_data}
            ]
        }

        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.post(self.BASE_URL, headers=headers, json=payload)
                
                # Check for HTTP errors and return the exact JSON message from OpenRouter
                if not response.is_success:
                    raise AIProviderError(f"API Error {response.status_code}: {response.text}")
                    
                data = response.json()
                return data["choices"][0]["message"]["content"].strip()
                
        except httpx.RequestError as e:
            raise AIProviderError(f"Network failure: {str(e)}")
        except (KeyError, IndexError, ValueError) as e:
            raise AIProviderError(f"Unexpected API response format: {str(e)}")