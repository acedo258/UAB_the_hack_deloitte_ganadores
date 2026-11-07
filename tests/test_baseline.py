"""Comparación con lo habitual (core/baseline.py): avisa en lo anómalo y calla en lo normal.
Ejecutar: python -m pytest -q"""
import pytest

from core.config import DB_PATH

pytestmark = pytest.mark.skipif(not DB_PATH.exists(), reason="ejecuta antes: python -m core.store")


def _bl(alert_id, cid):
    from core.context import build_pack
    return [c for c in build_pack(alert_id).checks if c.id == cid]


# ---- avisa en lo anómalo
def test_dominio_raro_primera_vez():
    c = _bl("ALR-20261009-011791", "BL.host_domain")
    assert any(x.attention and "aplihartom.com" in x.answer and "PRIMERA VEZ" in x.answer for x in c)


def test_pais_nuevo_desde_hosting_que_nadie_usa():
    c = _bl("ALR-20261007-011786", "BL.user_origin")
    assert any(x.attention and "NL" in x.answer for x in c)


def test_identidad_cloud_sin_historial():
    c = _bl("ALR-20261016-011821", "BL.key_origin")
    assert c and c[0].attention


def test_atacante_recurrente_no_se_vuelve_habitual():
    # Envenenamiento de la línea base: la 6.ª visita del atacante sigue siendo anómala
    c = _bl("ALR-20261028-011882", "BL.user_origin")
    assert c and c[0].attention and "ya alertado" in c[0].answer


# ---- calla en lo normal
def test_proveedor_legitimo_desde_su_ip():
    c = _bl("ALR-20261022-007268", "BL.user_origin")
    assert c and not c[0].attention and "habitual" in c[0].answer


def test_pais_nuevo_pero_infraestructura_comun():
    # Private Relay de Microsoft: lo usan cientos de empleados
    c = [x for x in _bl("ALR-20261009-001917", "BL.user_origin") if "FR" in x.answer]
    assert c and not c[0].attention and "infraestructura común" in c[0].answer


def test_ip_del_remitente_no_es_un_inicio_de_sesion():
    # La IP de un correo es del remitente: no se compara con el historial de la destinataria
    assert not _bl("ALR-20261009-011790", "BL.user_origin")


def test_ruido_sccm_sin_avisos():
    from core.context import build_pack
    assert not any(c.attention for c in build_pack("ALR-20261005-000301").checks)


# ---- herramienta para el modo investigador
def test_herramienta_baseline():
    from core.tools import ToolBox
    tb = ToolBox()
    r = tb.baseline("host_domain", "WS-BCN-1770", "aplihartom.com", "2026-10-09T10:00:00Z")
    assert r["attention"] and tb.trace[-1].tool == "baseline"
    assert "error" in tb.baseline("no_existe", "x")
