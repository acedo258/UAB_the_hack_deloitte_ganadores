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
    t = triage_alert("ALR-20261005-000301", use_cache=False)
    assert isinstance(t, Ticket)
    assert t.verdict in ("true_positive", "benign_true_positive", "false_positive", "needs_more_info")
    assert t.alert_ids == ["ALR-20261005-000301"]
