# Plan de trabajo por persona

Leyenda: ✅ ya está en el esqueleto · ⬜ por hacer · ⭐ imprescindible para el nivel 1

## Hitos comunes
| Hora | Qué tiene que funcionar | Nivel |
|---|---|---|
| Sáb 13:15 | Todos con el entorno arrancado y los tests en verde | — |
| Sáb 16:00 | Una alerta real triada con un LLM de verdad, vista en la consola | 1 |
| Sáb 20:00 | Las 150 de desarrollo triadas; primera nota de `eval/score.py`. **Si no es buena, no se empieza el 2** | 1 sólido |
| Dom 00:00 | Patrones aprobables en bloque sobre las 11.061 + correlación básica | 2 |
| Dom mañana | Vista de incidente (cadena de ataque) + contención con aprobación. Congelar y ensayar 2 veces | 3–4 |

Reglas: una rama por persona; merges pequeños a `main`; quien toque `core/schemas.py` avisa al grupo.

---

## A · Datos y herramientas (`core/store.py`, `core/tools.py`, `core/context.py`)
1. ✅ Carga de las 18 fuentes en DuckDB, `alerts`, `alert_entities` y `entity_events` (2,6 M filas, ~10 s).
2. ✅ Normalización de usuarios (UPN, `TARVIA\x`, username), hosts en mayúsculas y hora local con cambio de horario el 25/10.
3. ✅ Herramientas: `get_asset` (también rangos), `get_user` (+RRHH), `get_events`, `entity_timeline`, `search_logs`,
   `intel`, `matching_changes`, `alerts_for_entity`. Todas en < 150 ms.
4. ⭐⬜ Revisar `ENTITY_MAP` fuente a fuente: faltan entidades (p. ej. `cloudtrail.requestParameters.userName`,
   `email.attachments[].sha256`, `edr_events.details`, URLs de `email.urls`, `sql_audit.object`).
5. ⭐⬜ Afinar el pack por runbook: qué fuentes mirar primero en cada RB (RB-01 correo → `email_clicks`, `proxy`,
   `idp_signins` del usuario después del clic; RB-03 → `idp_audit` de la sesión; RB-06 → misma `accessKeyId`…).
6. ⬜ Entidades "hub" que inflan la línea temporal (IPs del proxy, `tarvia.example`): excluirlas o resumirlas.
7. ⬜ `matching_changes`: comprobar que todos los cambios del calendario se emparejan con sus alertas y nada más.
8. ⬜ Ingesta de alertas nuevas (las 10 del domingo): función que reciba un JSONL y lo añada a `alerts`.

**Terminado cuando:** cualquiera de las 150 alertas tiene un pack en < 1 s, < 16.000 caracteres y con todo lo que pide su runbook.

## B · Agente (`agent/`)
1. ✅ Cliente compatible con OpenAI (Ollama / Groq / mock), reintentos en 429, extracción de JSON (quita `<think>`).
2. ✅ Prompt base + runbook del dataset; texto no fiable fuera del JSON y delimitado.
3. ✅ Modo rápido con validación y reintento; si falla, `needs_more_info` (el sistema nunca se cae).
4. ✅ Modo investigador con herramientas (máx. 6 pasos). **Sin probar con un LLM real.**
5. ⭐⬜ Arrancar Ollama + `qwen3:8b` y crear la cuenta de Groq. Probar las 5 alertas de `fixtures/`.
6. ⭐⬜ Afinar el prompt con los fallos que dé `eval/score.py` (sin meter los casos del gold en el prompt).
7. ⬜ Notas por runbook en `agent/prompts/RB-0X.md` (se cargan solas si existen).
8. ⬜ Probar los dos intentos de manipulación (`ALR-20261020-011911`, `ALR-20261020-011897`): el LLM no debe bajar la severidad.
9. ⬜ Triaje de patrón: prompt que reciba el representante + 3 ejemplos + el recuento y proponga el veredicto para todo el patrón.

**Terminado cuando:** las 150 dan tickets válidos con un LLM real y ninguna manipulación funciona.

## C · Consola (`ui/`, `api/server.py`)
1. ✅ API: cola, patrones, alerta, evento crudo, ticket, triaje en directo (SSE), decisiones, contención vía API simulada.
2. ✅ Vue: Cola, Ticket (alerta · qué consultó la IA · conclusión · decisión de la persona), Patrones.
3. ✅ Contención: pide el token a `/approvals` y ejecuta; la API bloquea OT.
4. ⭐⬜ Ticket: marcar visualmente qué es de la IA y qué de la persona; pulir el aviso de manipulación.
5. ⬜ Vista Incidente: línea temporal de la cadena + grafo de entidades (`npm i cytoscape`).
6. ⬜ Cabecera con el embudo en directo: alertas → patrones → decisiones humanas → minutos ahorrados.
7. ⬜ Registro de decisiones y de contención (`/api/containment/log`).
8. ⬜ Modo demo: botón "triar las 10 alertas nuevas" que las lance una tras otra y las enseñe en directo.

**Terminado cuando:** en la demo se ve una alerta triarse en directo y una contención aprobada aparece en el registro.

## D · Criterio, evaluación y negocio (`core/policy.py`, `core/fingerprint.py`, `eval/`, `docs/`)
1. ✅ Matriz, ajustes ±1 (tope de un nivel), benign → informational/low, escalado obligatorio, aprobaciones, OT nunca. 6 tests.
2. ✅ Huellas: 11.061 → 95 patrones; los 10 atípicos ya salen solos.
3. ⭐⬜ `eval/gold.jsonl` con ~40 casos etiquetados a mano (lista abajo). **Nunca se pasan al agente.**
4. ⭐⬜ Medir cada 3 h con `python -m eval.score` y compartir la nota.
5. ⬜ Afinar `FIELDS` por regla (UC-EDR-003 sale con campos nulos; revisar UC-IDP-001 y UC-WEB-002).
6. ⬜ `core/correlate.py`: grafo de entidades con ventana de días, sin entidades hub; un ticket por incidente.
7. ⬜ Domingo: one-pager para el comité (alertas → decisiones, minutos ahorrados, cobertura nocturna, límites) y guion de la demo.

### Casos para el gold (historias encontradas en el análisis)
| Historia | Alertas de partida |
|---|---|
| Laura Ferrer: AiTM → regla de buzón → fraude IBAN 148.320 € | ALR-20261007-011785..011788, ALR-20261008-011789 |
| Marta Puig: Latrodectus → Cobalt Strike → LSASS → PsExec → shadow copies | ALR-20261009-011790/011791/011792/011793, ALR-20261010-011794..011798 |
| Persistencia posterior: alta en Domain Admins y parada del EDR | ALR-20261018-011895, ALR-20261018-011896 |
| Cadena de suministro → clave AWS → admin → exfiltración CRM | ALR-20261013-011901, ALR-20261015-011819/011820, ALR-20261016-011821 |
| Tienda 7: AnyDesk → RAM scraping TPV → C2 | ALR-20261012-011829, ALR-20261020-011897..011899, ALR-20261021-011900 |
| Lucía Castro: AiTM + phishing con prompt injection | ALR-20261020-011911..011914 |
| Minero en Jenkins | ALR-20261006-011825, ALR-20261006-011826 |
| Vela: fuga de datos por prompt injection | ALR-20261008-011823, ALR-20261008-011822 |
| ATO de clientes con tarjetas regalo + stuffing con éxitos | ALR-20261011-011802..011814 |
| Otros: fatiga MFA, svc_backup por Tor, Núria Vidal, spraying VPN, Logisoft desde IP ajena, mega.nz | ALR-20261010-011827, ALR-20261013-011816, ALR-20261015-011818, ALR-20261013-011815, ALR-20261011-011877, ALR-20261014-011817 |
| **Trampas (benignas)** | ALR-20261007-011874 (nómina), ALR-20261013-011869 (PsExec con cambio), ALR-20261024-011916 (EDR con cambio), ALR-20261017-011876 (mantenimiento OT), ALR-20261016-011922 (Logisoft con cambio), ALR-20261023-011915 (Backup Operators), ALR-20261012-003200 (puppeteer), ALR-20261005-000301 (SCCM) |

Verificad cada caso mirando los datos: esta lista es una hipótesis de partida, no la verdad.
