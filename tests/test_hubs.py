"""Hubs (core/store.py: build_hubs): lo que comparte todo el mundo se excluye; las entidades de los ataques, no.
Ejecutar: python -m pytest -q"""
import pytest

from core.config import DB_PATH

pytestmark = pytest.mark.skipif(not DB_PATH.exists(), reason="ejecuta antes: python -m core.store")


def test_hubs_evidentes():
    from core.store import hubs, is_hub
    for e in ("www.tarvia.example", "198.18.200.10", "DC01", "nt authority\\system", "sharepoint.com"):
        assert is_hub(e), e
    assert hubs()["www.tarvia.example"]["kind"] == "hub"


def test_entidades_de_los_ataques_no_son_hub():
    from core.store import is_hub
    for e in ("marta.puig", "WS-BCN-1770", "aplihartom.com", "svc_backup", "backup-sync", "77.90.185.20",
              "ext.logisoft", "nuria.vidal", "adm.aortega", "pedido_q4_2026.js", "WMS01", "cdn-wms-metrics.example"):
        assert not is_hub(e, include_campaigns=True), e


def test_campana_no_es_hub():
    # Phishing repetido de una sola regla: lo agrupa fingerprint, no se trata como hub
    from core.store import hubs, is_hub
    assert hubs()["micr0soft-365-billing.example"]["kind"] == "campaign"
    assert not is_hub("micr0soft-365-billing.example")
    assert is_hub("micr0soft-365-billing.example", include_campaigns=True)


def test_herramientas_no_relacionan_por_un_hub():
    from core.tools import ToolBox
    tb = ToolBox()
    assert tb.alerts_for_entity("www.tarvia.example", "2026-10-01T00:00:00Z", "2026-11-02T00:00:00Z") == []
    assert "hub" in tb.entity_timeline("DC01", "2026-10-09T00:00:00Z", "2026-10-10T00:00:00Z")


def test_pack_sin_hubs_ni_trafico_de_red_en_la_linea_temporal():
    from core.context import TIMELINE_SOURCES, build_pack
    from core.store import is_hub
    p = build_pack("ALR-20261009-001917")          # Elena, desde la salida de Orange (hub)
    assert not any(is_hub(x["entity"]) for x in p.timeline)
    assert any("hubs" in n for n in p.notes)
    p = build_pack("ALR-20261009-011791")          # Marta: 1.260 eventos de proxy que antes ahogaban todo
    assert p.timeline and all(x["source"] in TIMELINE_SOURCES for x in p.timeline)
