"""
OpenRouter AI Client.
Provides centralized, configurable connection to OpenRouter API with
robust error handling, environment-variable configuration, server-side fallback,
and structured JSON object response formatting.
"""

import os
import time
from typing import Optional, Dict, Any, List, Union, Tuple
import requests
from dotenv import load_dotenv

load_dotenv()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Primary default model read dynamically from OPENROUTER_MODEL
DEFAULT_MODEL = os.getenv("OPENROUTER_MODEL", "google/gemini-3-flash-preview")
DEFAULT_TIMEOUT = int(os.getenv("AI_TIMEOUT", "65"))
DEFAULT_MAX_TOKENS = int(os.getenv("AI_MAX_TOKENS", "8192"))
DEFAULT_TEMPERATURE = float(os.getenv("AI_TEMPERATURE", "0.1"))

# Up to 3 models for OpenRouter's single-call server-side fallback
FALLBACK_CANDIDATES = [
    "liquid/lfm-2.5-2.6b:free",
    "cohere/north-mini-code:free",
]


# Model families known to support OpenAI-style response_format: {"type": "json_object"}
JSON_MODE_SUPPORTED_PREFIXES = (
    "openai/",
    "meta-llama/llama-3",
    "mistralai/",
    "nvidia/",
    "google/",
    "deepseek/",
    "qwen/",
    "cohere/",
    "anthropic/",
)


def supports_json_mode(model_name: str) -> bool:
    """
    Determines whether a model/provider natively supports response_format: {"type": "json_object"}.
    If unsupported, the pipeline relies on strict prompt instructions and robust local JSON extraction.
    """
    if not model_name:
        return False
    lower = model_name.lower().strip()
    return any(lower.startswith(prefix) for prefix in JSON_MODE_SUPPORTED_PREFIXES)


def get_api_key() -> str:
    load_dotenv(override=True)
    key = os.getenv("OPENROUTER_API_KEY") or OPENROUTER_API_KEY or ""
    return key.strip()


def get_model() -> str:
    """Reads model dynamically from OPENROUTER_MODEL environment variable."""
    load_dotenv(override=True)
    return (os.getenv("OPENROUTER_MODEL") or DEFAULT_MODEL).strip()


def call_ai(
    system_prompt: str,
    user_prompt: str,
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
    timeout: Optional[int] = None,
    json_mode: bool = True,
    response_format: Optional[Dict[str, Any]] = None,
    models: Optional[List[str]] = None,
    return_meta: bool = False,
) -> Union[str, Tuple[str, Dict[str, Any]]]:
    """
    Executes exactly one completion call to OpenRouter.
    Utilizes OpenRouter's server-side models array (up to 3 items) for single-request fallback.
    Detects and applies response_format: {"type": "json_object"} ONLY when supported by the model.
    """
    api_key = get_api_key()
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY not found in environment variables or .env file.")

    primary_model = get_model()
    print(f"[AI] Model: {primary_model}")

    temp = DEFAULT_TEMPERATURE if temperature is None else temperature
    tokens = DEFAULT_MAX_TOKENS if max_tokens is None else max_tokens
    req_timeout = DEFAULT_TIMEOUT if timeout is None else timeout

    # Construct model list (max 3 allowed by OpenRouter)
    if models:
        model_list = models[:3]
    else:
        model_list = [primary_model]
        for candidate in FALLBACK_CANDIDATES:
            if candidate not in model_list and len(model_list) < 3:
                model_list.append(candidate)

    is_google_key = api_key.startswith("AQ.") or api_key.startswith("AIza")
    if is_google_key:
        api_url = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
        google_model = "gemini-3.6-flash"
        if "gemini" in primary_model.lower():
            # If specified as e.g. google/gemini-3-flash-preview, use gemini-3.6-flash
            google_model = "gemini-3.6-flash"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload: Dict[str, Any] = {
            "model": google_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temp,
            "max_tokens": max(tokens, 8192),
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        model_list = [google_model]
        print(f"[AI CLIENT] AI request started (Google OpenAI-compat: {google_model}, Timeout: {req_timeout}s)...")
    else:
        api_url = OPENROUTER_URL
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://securecode.ai",
            "X-Title": "SecureCode AI Security Analysis",
        }
        payload: Dict[str, Any] = {
            "models": model_list,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temp,
            "max_tokens": tokens,
        }
        # Only supply response_format if explicitly requested or verified compatible
        if response_format:
            payload["response_format"] = response_format
        elif json_mode and supports_json_mode(model_list[0]):
            payload["response_format"] = {"type": "json_object"}
        elif json_mode:
            print(f"[AI CLIENT] Model '{model_list[0]}' does not declare native json_object response_format; relying on strict JSON prompt and local Pydantic validation.")
        print(f"[AI CLIENT] AI request started (Primary: {model_list[0]}, Candidates: {model_list}, Timeout: {req_timeout}s)...")

    start_time = time.perf_counter()

    try:
        response = requests.post(
            api_url,
            headers=headers,
            json=payload,
            timeout=req_timeout,
        )
    except requests.exceptions.Timeout as exc:
        err_msg = f"OpenRouter request timed out after {req_timeout}s"
        print(f"[AI CLIENT] Failure reason: {err_msg}")
        raise TimeoutError(err_msg) from exc
    except requests.exceptions.RequestException as exc:
        err_msg = f"OpenRouter network request failed: {exc}"
        print(f"[AI CLIENT] Failure reason: {err_msg}")
        raise RuntimeError(err_msg) from exc

    # If Google returns temporary 503 (high demand spike), retry once after 2s
    if response.status_code == 503 and is_google_key:
        print("[AI CLIENT] Google endpoint returned 503 (temporary high demand spike). Retrying once after 2s...")
        time.sleep(2)
        try:
            response = requests.post(
                api_url,
                headers=headers,
                json=payload,
                timeout=req_timeout,
            )
        except Exception as exc:
            print(f"[AI CLIENT] Retry failed: {exc}")

    latency = time.perf_counter() - start_time

    if response.status_code != 200:
        err_msg = response.text[:400]
        print(f"[AI CLIENT] Failure reason: HTTP {response.status_code} - {err_msg}")
        raise RuntimeError(f"OpenRouter API returned HTTP {response.status_code}: {err_msg}")

    try:
        data = response.json()
    except Exception as exc:
        err_msg = f"Failed to parse OpenRouter response as JSON: {exc}"
        print(f"[AI CLIENT] Failure reason: {err_msg}")
        raise RuntimeError(err_msg) from exc

    choices = data.get("choices", [])
    if not choices:
        err_msg = f"OpenRouter returned no response choices. Raw: {data}"
        print(f"[AI CLIENT] Failure reason: {err_msg}")
        raise RuntimeError(err_msg)

    message = choices[0].get("message", {})
    content = message.get("content")
    used_model = data.get("model", model_list[0])

    # Fallback to reasoning if content is empty but reasoning contains text
    if not content and message.get("reasoning"):
        content = message.get("reasoning")

    print(f"[AI CLIENT] Response received (HTTP 200, Model used: {used_model}, Latency: {latency:.2f}s, Bytes: {len(content or '')})")

    if not content:
        err_msg = f"OpenRouter model {used_model} returned empty content."
        print(f"[AI CLIENT] Failure reason: {err_msg}")
        raise RuntimeError(err_msg)

    meta = {
        "model_used": used_model,
        "latency_seconds": round(latency, 3),
        "tokens_used": data.get("usage", {}).get("total_tokens", 0),
    }

    if return_meta:
        return content, meta
    return content