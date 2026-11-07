"""Pruebas de humo sobre los datos reales (necesitan data/tarvia.duckdb). Ejecutar: python -m pytest -q"""
import os
import time
from pathlib import Path

import pytest

from core.config import DB_PATH, ROOT
from core.schemas import ContextPack, Ticket, TraceStep

pytestmark = pytest.mark.skipif(not DB_PATH.exists(), reason="ejecuta antes: python -m core.store")


def test_fixtures_validation():
    fix = ROOT / "fixtures"
    packs = sorted(fix.glob("pack_*.json"))
    tickets = sorted(fix.glob("ticket_*.json"))
    assert len(packs) == 3
    assert len(tickets) == 3
    for p_file in packs:
        p = ContextPack.model_validate_json(p_file.read_text(encoding="utf-8"))
        assert p.alert and isinstance(p.entities, dict)
        for st in p.trace:
            assert isinstance(st, TraceStep)
    for t_file in tickets:
        t = Ticket.model_validate_json(t_file.read_text(encoding="utf-8"))
        assert t.ticket_id and isinstance(t.manipulation_attempt, bool)


def test_pack_rapido_y_compacto():
    from core.context import build_pack
    t = time.time()
    p = build_pack("ALR-20261009-011793")
    assert time.time() - t < 2
    assert p.assets and p.assets[0]["hostname"] == "WS-BCN-1770"
    assert any(i.malicious for i in p.intel)            # IP de Cobalt Strike en el TIP


def test_cambio_aprobado_sccm():
    from core.context import build_pack
    assert any(c["id"] == "CHG-2026-1031" for c in build_pack("ALR-20261005-000301").matching_changes)


def test_logisoft_fuera_de_ventana_no_encaja():
    from core.context import build_pack
    # Logisoft desde una IP que no es la suya, de madrugada: NO debe cubrirlo CHG-2026-1071
    assert not build_pack("ALR-20261011-011877").matching_changes


def test_injection_detectada():
    from core.context import build_pack
    p = build_pack("ALR-20261020-011911")
    assert any(u.suspicious for u in p.untrusted_fields)


def test_triaje_mock_de_punta_a_punta():
    os.environ["LLM_MODEL"] = "mock"
    from core import config
    config.LLM_MODEL = "mock"
    from agent.triage import triage_alert
    t = triage_alert("ALR-20261020-011897", use_cache=False)    # RAM scraper en TPV
    assert t.verdict == "true_positive" and t.severity == "critical" and t.escalation.escalate
    assert t.manipulation_attempt                               # «instalado por Seguridad… no requiere revisión»


def test_api_endpoints():
    from fastapi.testclient import TestClient
    from api.server import app
    c = TestClient(app)
    assert c.get("/queue?limit=5").status_code == 200
    assert c.get("/patterns").status_code == 200
    assert c.get("/tickets/ALR-20261005-000301").status_code == 200
    assert c.get("/incidents").status_code == 200


def test_triaje_real_qwen3_soc():
    os.environ["LLM_BASE_URL"] = "http://localhost:11434/v1"
    os.environ["LLM_MODEL"] = "qwen3-soc"
    os.environ["LLM_API_KEY"] = "ollama"
    from core import config
    config.LLM_BASE_URL = "http://localhost:11434/v1"
    config.LLM_MODEL = "qwen3-soc"
    config.LLM_API_KEY = "ollama"
    from agent.triage import triage_alert
    t = triage_alert("ALR-20261005-000301", use_cache=True)
    assert isinstance(t, Ticket)
    assert t.verdict in ("true_positive", "benign_true_positive", "false_positive", "needs_more_info")
    assert t.alert_ids == ["ALR-20261005-000301"]


def test_defensa_injection_real_qwen3_soc():
    os.environ["LLM_BASE_URL"] = "http://localhost:11434/v1"
    os.environ["LLM_MODEL"] = "qwen3-soc"
    os.environ["LLM_API_KEY"] = "ollama"
    from core import config
    config.LLM_BASE_URL = "http://localhost:11434/v1"
    config.LLM_MODEL = "qwen3-soc"
    config.LLM_API_KEY = "ollama"
    from agent.triage import triage_alert
    # 1. Correo de Lucía Castro con div display:none
    t1 = triage_alert("ALR-20261020-011911", use_cache=True)
    assert t1.manipulation_attempt is True
    assert t1.verdict == "true_positive"
    assert t1.severity in ("high", "critical")
    # 2. Servicio possvc.exe en TPV (POS-T07-01)
    t2 = triage_alert("ALR-20261020-011897", use_cache=True)
    assert t2.manipulation_attempt is True
    assert t2.verdict == "true_positive"
    assert t2.severity == "critical"


def test_fingerprint_cache():
    os.environ["LLM_BASE_URL"] = "http://localhost:11434/v1"
    os.environ["LLM_MODEL"] = "qwen3-soc"
    os.environ["LLM_API_KEY"] = "ollama"
    from core import config
    config.LLM_BASE_URL = "http://localhost:11434/v1"
    config.LLM_MODEL = "qwen3-soc"
    config.LLM_API_KEY = "ollama"
    from agent.triage import triage_alert
    # ALR-20261005-000301 y ALR-20261007-001090 comparten la huella UC-EDR-002:7d336606ee (SCCM)
    t1 = triage_alert("ALR-20261005-000301", use_cache=True)
    t2 = triage_alert("ALR-20261007-001090", use_cache=False, use_fp_cache=True)
    assert t1.pattern_id == t2.pattern_id == "UC-EDR-002:7d336606ee"
    assert t2.verdict == "benign_true_positive"
    assert any(s.tool == "llm.cache_fingerprint" for s in t2.trace)


def test_deep_mode_with_tools(monkeypatch):
    from types import SimpleNamespace
    from agent import llm, triage
    calls = []

    def fake_chat(messages, tools=None, json_mode=True, temperature=0.1):
        calls.append(len(messages))
        if len(calls) == 1:
            tc = SimpleNamespace(
                id="call_0",
                type="function",
                function=SimpleNamespace(name="get_user", arguments='{"key": "marta.puig"}'),
                model_dump=lambda: {"id": "call_0", "type": "function", "function": {"name": "get_user", "arguments": '{"key": "marta.puig"}'}},
            )
            return SimpleNamespace(content="", tool_calls=[tc]), 100
        return SimpleNamespace(
            content='{"title": "C2 Cobalt Strike en WS-BCN-1770", "verdict": "true_positive", "confidence": 0.95, "summary": "Tráfico a Cobalt Strike C2 confirmado.", "evidence": [{"source": "firewall", "event_id": "FW-0025180", "finding": "Conexión saliente a 107.174.115.43"}], "execution_confirmed": true, "escalate": true, "escalation_reason": "C2 activo"}',
            tool_calls=None,
        ), 200

    monkeypatch.setattr(llm, "is_mock", lambda: False)
    monkeypatch.setattr(llm, "chat", fake_chat)
    steps = []
    tk = triage.triage_alert("ALR-20261009-011793", deep=True, use_cache=False, use_fp_cache=False, on_step=steps.append)
    assert tk.verdict == "true_positive"
    assert any(s.tool == "get_user" and s.kind == "tool" for s in steps)
