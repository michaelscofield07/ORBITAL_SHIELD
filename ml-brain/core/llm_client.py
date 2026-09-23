"""
ORBITAL SHIELD — ML Correlation Brain
MODEL 3: LLM Client for Secure & Recover Guidance

Connects to local Ollama instance (http://localhost:11434) to query:
  - Primary Model:  deepseek-r1:14b (advanced reasoning, <think> tags stripped)
  - Fallback Model: qwen2.5:14b     (fast, reliable JSON fallback)

Enforces:
  - Non-streaming JSON mode (format="json")
  - Thinking tag stripping (<think>...</think>)
  - Fallback logic: tries primary, falls back to secondary on any error
  - Raises LLMUnavailableError only if both fail
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import httpx
import yaml

logger = logging.getLogger("orbital.llm_client")

_CONFIG_PATH = Path(__file__).parent.parent / "config" / "rules.yaml"


class LLMUnavailableError(Exception):
    """Raised when both primary and fallback LLM models fail or are unreachable."""
    pass


def load_model3_config() -> Dict[str, Any]:
    """Loads model3 configuration block from rules.yaml."""
    default_config = {
        "ollama_host": "http://localhost:11434",
        "primary_model": "deepseek-r1:14b",
        "fallback_model": "qwen3:14b",
        "timeout_seconds": 180,
        "max_open_incidents_to_process": 10,
        "verification_min_window_seconds": 15,
    }
    if not _CONFIG_PATH.exists():
        return default_config
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
            m3_cfg = cfg.get("model3", {})
            return {**default_config, **m3_cfg}
    except Exception as exc:
        logger.warning("Failed to load model3 config from %s (%s) — using defaults", _CONFIG_PATH, exc)
        return default_config


def strip_thinking(text: str) -> str:
    """
    Strips DeepSeek-R1's <think>...</think> block from the output text.
    Handles multiline reasoning output cleanly.
    """
    if not text:
        return ""
    # Strip full closed think tags
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    # Also handle unclosed <think> tag if output was truncated
    cleaned = re.sub(r"<think>.*", "", cleaned, flags=re.DOTALL)
    return cleaned.strip()


def extract_json(text: str) -> Dict[str, Any]:
    """
    Extracts and parses JSON from model output.
    Handles raw JSON, markdown ```json ... ``` blocks, and text containing think tags.
    """
    cleaned = strip_thinking(text)
    if not cleaned:
        raise ValueError("Model output is empty after stripping reasoning blocks.")

    # 1. Attempt direct JSON parsing
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # 2. Check for markdown fenced JSON codeblocks
    fenced_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, flags=re.DOTALL)
    if fenced_match:
        try:
            return json.loads(fenced_match.group(1))
        except json.JSONDecodeError:
            pass

    # 3. Locate outer-most JSON curly braces { ... }
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        json_candidate = cleaned[first_brace:last_brace + 1]
        try:
            return json.loads(json_candidate)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Extracted JSON block from model was invalid: {exc}") from exc

    raise ValueError(f"Could not locate a valid JSON object in model output: {cleaned[:200]}...")


def chat_json(
    system_prompt: str,
    user_prompt: str,
    model: str,
    ollama_host: Optional[str] = None,
    timeout: Optional[float] = None
) -> Dict[str, Any]:
    """
    Sends a chat completion request to the Ollama /api/chat endpoint with format="json".

    Args:
        system_prompt: System directive specifying role and schema constraints.
        user_prompt: User/incident content.
        model: Ollama model name (e.g., 'deepseek-r1:14b').
        ollama_host: Ollama server base URL (default from config or http://localhost:11434).
        timeout: Request timeout in seconds.

    Returns:
        Parsed JSON dictionary from the model response.
    """
    cfg = load_model3_config()
    host = (ollama_host or cfg.get("ollama_host", "http://localhost:11434")).rstrip("/")
    t_out = timeout if timeout is not None else float(cfg.get("timeout_seconds", 180))

    url = f"{host}/api/chat"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "stream": False,
        "format": "json"
    }

    try:
        with httpx.Client(timeout=t_out) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Ollama HTTP error on model {model} ({url}): {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"Unexpected error communicating with Ollama ({url}): {exc}") from exc

    message_content = data.get("message", {}).get("content", "")
    if not message_content:
        raise ValueError(f"Empty content returned from Ollama model {model}")

    return extract_json(message_content)


def generate_with_fallback(
    system_prompt: str,
    user_prompt: str
) -> Tuple[Dict[str, Any], str]:
    """
    Executes guidance generation using primary model (deepseek-r1:14b),
    falling back to secondary model (qwen3:14b) on any failure.

    Returns:
        Tuple of (parsed_guidance_dict, model_name_used).

    Raises:
        LLMUnavailableError: If both primary and fallback models fail.
    """
    cfg = load_model3_config()
    primary = cfg.get("primary_model", "deepseek-r1:14b")
    fallback = cfg.get("fallback_model", "qwen3:14b")
    host = cfg.get("ollama_host", "http://localhost:11434")
    timeout = float(cfg.get("timeout_seconds", 180))

    # 1. Try Primary Model
    try:
        logger.info("Attempting Model 3 LLM generation using primary model: %s", primary)
        result = chat_json(system_prompt, user_prompt, model=primary, ollama_host=host, timeout=timeout)
        logger.info("Model 3 LLM generation succeeded with primary model: %s", primary)
        return result, primary
    except Exception as exc:
        logger.warning(
            "Primary LLM %s failed (%s). Falling back to secondary model: %s",
            primary, exc, fallback
        )

    # 2. Try Fallback Model
    try:
        logger.info("Attempting Model 3 LLM generation using fallback model: %s", fallback)
        result = chat_json(system_prompt, user_prompt, model=fallback, ollama_host=host, timeout=timeout)
        logger.info("Model 3 LLM generation succeeded with fallback model: %s", fallback)
        return result, fallback
    except Exception as exc:
        logger.error(
            "Fallback LLM %s also failed (%s). Both LLMs unavailable.",
            fallback, exc
        )
        raise LLMUnavailableError(
            f"All configured LLMs ({primary}, {fallback}) failed or are unreachable at {host}: {exc}"
        ) from exc


async def warmup_models_async(host: Optional[str] = None) -> None:
    """
    Sends non-blocking warm-up pings to primary and fallback models so Ollama loads
    their weights into memory/VRAM on startup before live requests arrive.
    """
    cfg = load_model3_config()
    target_host = (host or cfg.get("ollama_host", "http://localhost:11434")).rstrip("/")
    models = [cfg.get("primary_model", "deepseek-r1:14b"), cfg.get("fallback_model", "qwen3:14b")]
    
    logger.info("Starting background model warmup for: %s at %s", models, target_host)
    async with httpx.AsyncClient(timeout=180.0) as client:
        for m in models:
            try:
                resp = await client.post(
                    f"{target_host}/api/chat",
                    json={
                        "model": m,
                        "messages": [{"role": "user", "content": "Return JSON: {\"warmup\": true}"}],
                        "format": "json",
                        "stream": False,
                        "options": {"num_predict": 10}
                    }
                )
                if resp.status_code == 200:
                    logger.info("Warmup complete for %s (status=200)", m)
                else:
                    logger.warning("Warmup probe for %s returned status=%d", m, resp.status_code)
            except Exception as exc:
                logger.warning("Warmup probe for %s encountered: %s", m, exc)


def warmup_models(host: Optional[str] = None) -> None:
    """Synchronous model warmup helper for scripts or testing."""
    import asyncio
    try:
        asyncio.run(warmup_models_async(host))
    except Exception as exc:
        logger.warning("Synchronous warmup failed: %s", exc)

