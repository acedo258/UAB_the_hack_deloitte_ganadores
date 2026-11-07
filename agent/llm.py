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
    return os.getenv("LLM_MODEL", config.LLM_MODEL) == "mock"


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
    for i in range(len(out) - 1, -1, -1):
        if out[i].get("role") == "user" and isinstance(out[i].get("content"), str):
            if "/no_think" not in out[i]["content"]:
                out[i]["content"] = out[i]["content"].rstrip() + " /no_think"
            break
    return out


CHARS_PER_TOKEN = 2.8      # estimación conservadora para JSON en español con el tokenizador de Qwen
ANSWER_TOKENS = 1536       # sitio para el JSON de respuesta
TOOLS_TOKENS = 1024        # sitio para la descripción de las herramientas (modo investigador)


def num_ctx() -> int:
    """Ventana de contexto que se pide a Ollama. Con 8192, el pack más grande + prompt + runbook + respuesta pasa de
    8.000 tokens y Ollama recorta por el PRINCIPIO, que es donde están las reglas. 12288 cubre el peor caso medido
    (~9.400 tokens en modo rápido, ~10.400 con herramientas). Es fijo a propósito: si cambia entre llamadas, Ollama
    recarga el modelo. Se cambia con LLM_NUM_CTX."""
    return int(os.getenv("LLM_NUM_CTX", "12288"))


def estimate_tokens(messages: list[dict], tools: list[dict] | None = None) -> int:
    """Tokens aproximados de la petición más la respuesta, para avisar en la traza si no cabe."""
    chars = sum(len(m.get("content") or "") for m in messages)
    return int(chars / CHARS_PER_TOKEN) + ANSWER_TOKENS + (TOOLS_TOKENS if tools else 0)


def chat(messages: list[dict], tools: list[dict] | None = None, json_mode: bool = True, temperature: float = 0.1) -> Any:
    """Devuelve el mensaje del asistente (objeto OpenAI). Reintenta en 429 respetando el límite de Groq."""
    model = os.getenv("LLM_MODEL", config.LLM_MODEL)
    base_url = os.getenv("LLM_BASE_URL", config.LLM_BASE_URL)
    msgs = _apply_no_think(messages, model)
    # Ollama local con Qwen3: usar /api/chat con think=False evita que /v1/chat/completions fuerce <think>
    if "11434" in base_url and "qwen" in model.lower():
        try:
            import httpx
            from types import SimpleNamespace
            api_chat_url = base_url.replace("/v1", "").rstrip("/") + "/api/chat"
            ollama_msgs = []
            for m in msgs:
                om = {"role": m["role"], "content": m.get("content") or ""}
                if m.get("tool_calls"):
                    om["tool_calls"] = [
                        {"function": {"name": tc["function"]["name"],
                                      "arguments": json.loads(tc["function"]["arguments"]) if isinstance(tc["function"]["arguments"], str) else tc["function"]["arguments"]}}
                        for tc in m["tool_calls"]
                    ]
                ollama_msgs.append(om)
            payload: dict[str, Any] = {
                "model": model,
                "messages": ollama_msgs,
                "stream": False,
                "think": False,
                "options": {"temperature": temperature, "num_ctx": num_ctx()},
            }
            if tools:
                payload["tools"] = tools
            elif json_mode:
                payload["format"] = "json"
            r = httpx.post(api_chat_url, json=payload, timeout=config.LLM_TIMEOUT_S)
            r.raise_for_status()
            data = r.json()
            tokens = (data.get("prompt_eval_count") or 0) + (data.get("eval_count") or 0)
            raw_tcs = data["message"].get("tool_calls") or []
            tcs = []
            for idx, tc in enumerate(raw_tcs):
                fn = tc.get("function", {})
                args_str = json.dumps(fn.get("arguments", {}), ensure_ascii=False)
                tc_obj = SimpleNamespace(
                    id=f"call_{idx}",
                    type="function",
                    function=SimpleNamespace(name=fn.get("name", ""), arguments=args_str),
                    model_dump=lambda i=idx, n=fn.get("name", ""), a=args_str: {
                        "id": f"call_{i}", "type": "function", "function": {"name": n, "arguments": a}
                    },
                )
                tcs.append(tc_obj)
            return SimpleNamespace(content=data["message"].get("content", ""), tool_calls=tcs or None), tokens
        except Exception as e:  # noqa: BLE001
            # Solo se cae al endpoint /v1 si /api/chat no existe. Antes cualquier fallo (un timeout, por ejemplo)
            # repetía la petición por /v1 sin num_ctx ni think=False: la alerta tardaba el doble o el triple y
            # acababa igualmente "sin triaje automático".
            status = getattr(getattr(e, "response", None), "status_code", None)
            if not (isinstance(e, ImportError) or status == 404):
                raise

    kwargs: dict[str, Any] = {"model": model, "messages": msgs, "temperature": temperature}
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
