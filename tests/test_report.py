"""Informe de incidente (core/report.py): cumple el esquema de Deloitte y la contención respeta la política.
Ejecutar: python -m pytest -q"""
import json

import pytest

from core.config import DB_PATH, DATA_DIR

pytestmark = pytest.mark.skipif(not DB_PATH.exists(), reason="ejecuta antes: python -m core.store")

SCHEMA = json.loads((DATA_DIR / "01_contexto" / "informe_incidente.schema.json").read_text(encoding="utf-8"))
PY_TYPE = {"string": str, "array": list, "object": dict, "number": (int, float)}


@pytest.fixture(scope="module")
def reports():
    from core.report import build_reports
    return build_reports()


def _by_alert(reports, alert_id):
    r = [x for x in reports if alert_id in x["alert_ids"]]
    assert r, alert_id
    return r[0]


def test_cumple_el_esquema_de_deloitte(reports):
    assert reports
    for r in reports:
        for k in SCHEMA["required"]:
            assert k in r and r[k] not in (None, "", []), (r["incident_id"], k)
        for k, spec in SCHEMA["properties"].items():
            if k in r:
                assert isinstance(r[k], PY_TYPE[spec["type"]]), (r["incident_id"], k)
        assert all({"timestamp", "event_id", "description"} <= set(t) for t in r["timeline"])
        assert all({"action", "target", "approver"} <= set(p) for p in r["containment_plan"])
        assert 0 <= r["confidence"] <= 1


def test_cronologia_ordenada_y_citable(reports):
    from core.tools import PREFIX_SOURCE
    for r in reports:
        ts = [t["timestamp"] for t in r["timeline"]]
        assert ts == sorted(ts)
        assert all(t["event_id"].split("-")[0] in PREFIX_SOURCE or t["event_id"].startswith("ALR-") for t in r["timeline"])


def test_informe_de_la_cadena_del_adjunto(reports):
    r = _by_alert(reports, "ALR-20261009-011790")
    assert "marta.puig" in r["patient_zero"] and "UC-EML-002" in r["initial_access"]
    assert any(t["event_id"] == "EDR-0123400" for t in r["timeline"])
    assert r["severity"] == "critical"
    acts = {(p["action"], p["target"]) for p in r["containment_plan"]}
    assert ("isolate_host", "WS-BCN-1770") in acts and ("block_ioc", "aplihartom.com") in acts


def test_aprobaciones_segun_la_politica(reports):
    r = _by_alert(reports, "ALR-20261009-011790")
    plan = {(p["action"], p["target"]): p for p in r["containment_plan"]}
    assert not plan[("block_ioc", "aplihartom.com")]["requires_approval"]           # el N1 bloquea IOC
    assert plan[("isolate_host", "WS-BCN-1770")]["approver"] == "N2"                 # puesto: N2
    assert "responsable del servicio" in plan[("isolate_host", "FS01")]["approver"]  # servidor: N2 + servicio
    tpv = _by_alert(reports, "ALR-20261020-011897")
    assert any(p["target"].startswith("POS-") and "negocio" in p["approver"] for p in tpv["containment_plan"])


def test_nunca_se_actua_sobre_ot(reports):
    from core.store import rows
    ot = {r["h"] for r in rows("SELECT upper(hostname) h FROM activos WHERE zone = 'LOGISTICS-OT'")}
    for r in reports:
        for p in r["containment_plan"]:
            if p["target"].upper() in ot:
                assert p["action"] == "escalate" and not p["executable"]


def test_notificaciones_por_regla(reports):
    assert any("DPO" in n and "72 h" in n for n in _by_alert(reports, "ALR-20261016-011821")["notifications"])  # 112 GB del CRM
    assert any("PCI" in n for n in _by_alert(reports, "ALR-20261020-011897")["notifications"])                  # TPV
    assert any("Tesorería" in n for n in _by_alert(reports, "ALR-20261007-011786")["notifications"])            # cambio de IBAN


def test_cuentas_de_cliente_se_resetean_no_se_deshabilitan(reports):
    r = _by_alert(reports, "ALR-20261011-011802")
    assert not any(p["action"] == "disable_user" and p["target"].startswith("C7") for p in r["containment_plan"])
    assert any(p["action"] == "reset_password" and p["target"].startswith("C7") for p in r["containment_plan"])


def test_severidad_del_incidente_con_la_matriz():
    from core.correlate import compute_incidents
    for i in compute_incidents():
        assert i["severity_rationale"] and "×" in i["severity_rationale"]
