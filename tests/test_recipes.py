"""Recetas por runbook (core/recipes.py): cada test fija una pista que el pack TIENE que traer.
Ejecutar: python -m pytest -q"""
import json
import time

import pytest

from core.config import DB_PATH, PACK_MAX_CHARS

pytestmark = pytest.mark.skipif(not DB_PATH.exists(), reason="ejecuta antes: python -m core.store")


def _check(alert_id, check_id):
    from core.context import build_pack
    p = build_pack(alert_id)
    c = next((c for c in p.checks if c.id == check_id), None)
    assert c is not None, f"{alert_id} no tiene la comprobación {check_id}: {[c.id for c in p.checks]}"
    return c


def test_rb01_adjunto_ejecutado():
    c = _check("ALR-20261009-011790", "RB-01.ejecucion")
    assert c.attention and "WS-BCN-1770" in c.answer


def test_rb02_dominio_raro_tras_ejecucion():
    c = _check("ALR-20261009-011791", "RB-02.red")
    assert c.attention and "aplihartom.com" in c.answer


def test_rb03_persistencia_en_buzon():
    c = _check("ALR-20261007-011786", "RB-03.despues")
    assert c.attention and "New-InboxRule" in c.answer


def test_rb03_spraying_con_acceso_correcto():
    c = _check("ALR-20261013-011815", "RB-03.spraying")
    assert c.attention and "svc_backup" in c.answer


def test_rb04_consultas_masivas_y_correo_personal():
    assert _check("ALR-20261014-011817", "RB-04.sql").attention
    assert _check("ALR-20261014-011817", "RB-04.correo").attention


def test_rb06_quien_creo_la_identidad():
    c = _check("ALR-20261016-011821", "RB-06.origen")
    assert "svc_ecom_deploy" in c.answer


def test_rb07_herramienta_con_otro_cliente():
    c = _check("ALR-20261008-011823", "RB-07.conversacion")
    assert c.attention and "OTRO cliente" in c.answer


def test_rb08_origen_autorizado_no_avisa():
    assert not _check("ALR-20261009-002231", "RB-08.trafico").attention


def test_rb10_secretos_y_paquete_nuevo():
    assert "AWS_" in _check("ALR-20261013-011901", "RB-10.build").answer
    assert _check("ALR-20261013-011901", "RB-10.paquete").attention


def test_ruido_no_dispara_avisos():
    # SCCM con cambio aprobado: ninguna comprobación debe avisar
    from core.context import build_pack
    assert not any(c.attention for c in build_pack("ALR-20261005-000301").checks)


def test_eventos_citables_y_pack_dentro_de_limites():
    from core.context import build_pack
    for aid in ("ALR-20261009-011790", "ALR-20261007-011786", "ALR-20261014-011817"):
        t = time.time()
        p = build_pack(aid)
        assert time.time() - t < 1
        assert len(json.dumps(p.model_dump(exclude={"trace"}), ensure_ascii=False, default=str)) <= PACK_MAX_CHARS
        # las recetas quedan en la traza para que la consola enseñe "qué consultó la IA"
        assert any(s.tool.startswith("recipe.") for s in p.trace)
