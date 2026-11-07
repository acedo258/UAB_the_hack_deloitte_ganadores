"""Correlación de incidentes (core/correlate.py): las cadenas se unen y las trampas de actividad autorizada no.
La primera ejecución construye el pack de las ~200 candidatas (~30 s); después usa data/cache/incidents.json.
Ejecutar: python -m pytest -q"""
import pytest

from core.config import DB_PATH

pytestmark = pytest.mark.skipif(not DB_PATH.exists(), reason="ejecuta antes: python -m core.store")


@pytest.fixture(scope="module")
def incs():
    from core.correlate import compute_incidents
    return compute_incidents()


def _with(incs, alert_id):
    found = [i for i in incs if alert_id in i["alerts"]]
    assert found, f"{alert_id} no está en ningún incidente"
    return found[0]


def test_formato_para_la_consola(incs):
    keys = {"incident_id", "title", "severity", "status", "primary_entity", "impact_summary", "alerts", "timeline", "nodes", "edges"}
    for i in incs:
        assert keys <= set(i), i["incident_id"]
        assert len(i["alerts"]) >= 2 and len(i["rules"]) >= 2          # una cadena, no una repetición
        assert all({"ts", "phase", "event"} <= set(t) for t in i["timeline"])
        ids = {n["id"] for n in i["nodes"]}
        assert all(e["source"] in ids and e["target"] in ids for e in i["edges"])


def test_sin_hubs_en_los_grafos(incs):
    from core.store import is_hub
    assert not any(is_hub(n["label"], include_campaigns=True) for i in incs for n in i["nodes"])


def test_cadena_del_adjunto_hasta_el_borrado_de_copias_y_su_vuelta(incs):
    i = _with(incs, "ALR-20261009-011790")                  # correo con el adjunto
    for aid in ("ALR-20261009-011791", "ALR-20261010-011798", "ALR-20261018-011895"):   # ejecución, VSS, vuelta 18/10
        assert aid in i["alerts"], aid


def test_psexec_autorizado_desde_jump01_no_se_cuela(incs):
    # Mismo servidor días después no relaciona: la infraestructura solo une alertas a <= 48 h
    i = _with(incs, "ALR-20261009-011790")
    assert not {"ALR-20261013-011869", "ALR-20261013-011870", "ALR-20261013-011871", "ALR-20261013-011872"} & set(i["alerts"])


def test_cadena_de_suministro_sin_paquetes_legitimos(incs):
    from core.store import rows
    i = _with(incs, "ALR-20261013-011901")                  # dependency confusion
    assert "ALR-20261016-011821" in i["alerts"]              # unida a la descarga masiva por la clave que leyó el build
    legit = {r["alert_id"] for r in rows("SELECT alert_id FROM alerts WHERE rule_id = 'UC-DEV-001' AND alert_id <> 'ALR-20261013-011901'")}
    assert not legit & set(i["alerts"])


def test_spraying_unido_a_la_cuenta_que_entro(incs):
    i = _with(incs, "ALR-20261013-011815")
    assert any(l["entity"] == "svc_backup" and any("RB-03.spraying" in f for f in l["from"]) for l in i["links"])


def test_tienda_por_red_plana(incs):
    i = _with(incs, "ALR-20261012-011829")                  # AnyDesk en el portátil de la tienda
    assert any(l["type"] == "site" for l in i["links"]) and len(i["alerts"]) >= 4
