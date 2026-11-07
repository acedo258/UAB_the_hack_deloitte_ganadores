"""Cliente LLM único para todo el proyecto.  Responsable: B (agente).

Cualquier endpoint compatible con OpenAI:
  Ollama local : LLM_BASE_URL=http://localhost:11434/v1  LLM_MODEL=qwen3-soc      LLM_API_KEY=ollama
  Groq         : LLM_BASE_URL=https://api.groq.com/openai/v1  LLM_MODEL=qwen/qwen3.8-27b  LLM_API_KEY=gsk_...
  Sin LLM      : LLM_MODEL=mock   (heurística determinista para desarrollar la UI y los tests)
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any

from pydantic import ValidationError

from core import config
from core.schemas import ContextPack, Evidence, LLMTriage

_client = None
_client_cfg: tuple[str, str] | None = None


def is_mock() -> bool:
    return config.LLM_MODEL == "mock"


def client():
    global _client, _client_cfg
    base_url = os.getenv("LLM_BASE_URL", config.LLM_BASE_URL)
    api_key = os.getenv("LLM_API_KEY", config.LLM_API_KEY)
    if _client is None or _client_cfg != (base_url, api_key):
        from openai import OpenAI
        _client = OpenAI(base_url=base_url, api_key=api_key, timeout=config.LLM_TIMEOUT_S, max_retries=2)
        _client_cfg = (base_url, api_key)
    return _client


def _apply_no_think(messages: list[dict], model: str) -> list[dict]:
    """Desactiva el bloque de pensamiento en modelos Qwen3 añadiendo /no_think."""
    if "qwen" not in model.lower():
        return messages
    out = [dict(m) for m in messages]
    for m in out:
        if m.get("role") == "system" and isinstance(m.get("content"), str):
            if "/no_think" not in m["content"]:
                m["content"] = "/no_think\n" + m["content"]
            break
    for i in range(len(out) - 1, -1, -1):
        if out[i].get("role") == "user" and isinstance(out[i].get("content"), str):
            if "/no_think" not in out[i]["content"]:
                out[i]["content"] = "/no_think\n" + out[i]["content"]
            break
    return out


def chat(messages: list[dict], tools: list[dict] | None = None, json_mode: bool = True, temperature: float = 0.1) -> Any:
    """Devuelve el mensaje del asistente (objeto OpenAI). Reintenta en 429 respetando el límite de Groq."""
    model = os.getenv("LLM_MODEL", config.LLM_MODEL)
    base_url = os.getenv("LLM_BASE_URL", config.LLM_BASE_URL)
    msgs = _apply_no_think(messages, model)
    kwargs: dict[str, Any] = {"model": model, "messages": msgs, "temperature": temperature}
    if "11434" in base_url and "qwen" in model.lower():
        kwargs["extra_body"] = {"think": False}
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
            if "extra_body" in kwargs and ("think" in msg or "400" in msg):
                kwargs.pop("extra_body", None)
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


def triage_with_validation(messages: list[dict], pack: ContextPack | None = None) -> tuple[LLMTriage, int]:
    """Ejecuta el LLM, valida con Pydantic (1 reintento si falla) y hace fallback a needs_more_info."""
    msgs = list(messages)
    total_tokens = 0
    last_err = ""
    for _ in range(2):
        try:
            msg, tokens = chat(msgs)
            total_tokens += tokens
            return LLMTriage.model_validate(extract_json(msg.content)), total_tokens
        except (ValueError, ValidationError, Exception) as e:  # noqa: BLE001
            last_err = str(e)
            content = getattr(msg, "content", "") if "msg" in locals() else ""
            msgs += [
                {"role": "assistant", "content": content or ""},
                {"role": "user", "content": f"Tu JSON no es válido: {last_err[:500]}. Devuelve SOLO el JSON corregido. /no_think"},
            ]
    alert = pack.alert if pack else {}
    aid = alert.get("alert_id", "unknown")
    return LLMTriage(
        title=f"{alert.get('rule_name', 'Alerta')} (sin triaje automático)",
        verdict="needs_more_info",
        confidence=0.0,
        summary=f"El agente no pudo validar la salida tras reintento: {last_err[:200]}. Requiere revisión humana.",
        evidence=[Evidence(source="siem", event_id=aid, finding=alert.get("description", ""))],
        open_questions=["Fallo de validación del LLM: triar manualmente"],
    ), total_tokens
