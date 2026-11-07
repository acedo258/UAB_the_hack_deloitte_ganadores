"""Nivel 1: el pack no da falsas alarmas en el ruido típico y resume lo que dicen los datos.
Ejecutar: python -m pytest -q"""
import json
from pathlib import Path

import pytest

from core.config import DB_PATH

pytestmark = pytest.mark.skipif(not DB_PATH.exists(), reason="ejecuta antes: python -m core.store")


def _pack(aid):
    from core.context import build_pack
    return build_pack(aid)


def test_resumen_es_la_primera_comprobacion():
    p = _pack("ALR-20261009-011790")
    r = p.checks[0]
    assert r.id == "RESUMEN" and r.attention and "RB-01.ejecucion" in r.answer
    assert any(s.tool == "resumen" for s in p.trace)


@pytest.mark.parametrize("aid", ["ALR-20261005-000440",    # WAF bloqueado
                                 "ALR-20261005-000143",    # telemetría de Teams
                                 "ALR-20261005-000370"])   # correo interno de RRHH
def test_ruido_tipico_sin_senales(aid):
    p = _pack(aid)
    assert not p.checks[0].attention and "Ninguna" in p.checks[0].answer
    assert not any(c.attention for c in p.checks)


def test_teams_conocido_benigno_en_el_resumen():
    assert "teams.microsoft.com" in _pack("ALR-20261005-000143").checks[0].answer


def test_remitente_interno_y_sin_historial():
    p = _pack("ALR-20261005-000370")
    c = {x.id: x for x in p.checks}
    assert "INTERNO" in c["RB-01.remitente"].answer and "inicio de los logs" in c["RB-01.remitente"].answer
    assert not c["RB-01.logins"].attention and "sin historial suficiente" in c["RB-01.logins"].answer


def test_hub_en_inteligencia_no_es_desconocido():
    p = _pack("ALR-20261005-000370")
    i = [x for x in p.intel if x.indicator == "tarvia.example"][0]
    assert "no es un indicador" in i.result


def test_resumen_avisa_de_manipulacion():
    assert "manipulación" in _pack("ALR-20261020-011911").checks[0].answer


def test_cobertura_con_casos_propios(tmp_path):
    from eval.pack_coverage import check, expected_events
    assert expected_events({"alert_id": "x", "nota": "ver EDR-0123400 y SIGN-0083865"}) == ["EDR-0123400", "SIGN-0083865"]
    r = check("ALR-20261009-011790", ["EDR-0123400", "EDR-9999999"])
    assert r["found"] == 1 and r["missing"][0]["event_id"] == "EDR-9999999" and not r["missing"][0]["exists_in_db"]
