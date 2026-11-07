"""Cliente LLM único para todo el proyecto.  Responsable: B (agente).

Cualquier endpoint compatible con OpenAI:
  Ollama local : LLM_BASE_URL=http://localhost:11434/v1  LLM_MODEL=qwen3:8b       LLM_API_KEY=ollama
  Groq         : LLM_BASE_URL=https://api.groq.com/openai/v1  LLM_MODEL=qwen/qwen3.8-27b  LLM_API_KEY=gsk_...
  Sin LLM      : LLM_MODEL=mock   (heurística determinista para desarrollar la UI y los tests)
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any

from core import config

_client = None


def is_mock() -> bool:
    return config.LLM_MODEL == "mock"


def client():
    global _client
    if _client is None:
        from openai import OpenAI
        _client = OpenAI(base_url=config.LLM_BASE_URL, api_key=config.LLM_API_KEY, timeout=config.LLM_TIMEOUT_S, max_retries=2)
    return _client


def chat(messages: list[dict], tools: list[dict] | None = None, json_mode: bool = True, temperature: float = 0.1) -> Any:
    """Devuelve el mensaje del asistente (objeto OpenAI). Reintenta en 429 respetando el límite de Groq."""
    kwargs: dict[str, Any] = {"model": config.LLM_MODEL, "messages": messages, "temperature": temperature}
    if tools:
        kwargs["tools"] = tools
    elif json_mode:
        kwargs["response_format"] = {"type": "json_object"}
    for attempt in range(4):
        try:
            r = client().chat.completions.create(**kwargs)
            return r.choices[0].message, (r.usage.total_tokens if r.usage else 0)
        except Exception as e:  # noqa: BLE001
            msg = str(e)
            if ("429" in msg or "rate" in msg.lower()) and attempt < 3:
                time.sleep(int(os.getenv("LLM_RATE_SLEEP", "20")) * (attempt + 1))
                continue
            if "response_format" in msg and "response_format" in kwargs:   # proveedor sin modo JSON
                kwargs.pop("response_format")
                continue
            raise


def extract_json(text: str) -> dict:
    """Saca el JSON de la respuesta (quita <think>…</think> de Qwen y bloques ```json)."""
    text = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S).strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < 0:
        raise ValueError("la respuesta no contiene JSON")
    return json.loads(text[start: end + 1])
