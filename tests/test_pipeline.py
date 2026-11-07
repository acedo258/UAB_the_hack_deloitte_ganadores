"""Pruebas de humo sobre los datos reales (necesitan data/tarvia.duckdb). Ejecutar: python -m pytest -q"""
import os
import time

import pytest

from core.config import DB_PATH

pytestmark = pytest.mark.skipif(not DB_PATH.exists(), reason="ejecuta antes: python -m core.store")


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
