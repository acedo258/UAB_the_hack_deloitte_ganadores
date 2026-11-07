# SOC N1 · Tarvia — triaje de nivel 1 con agentes de IA

Hackathon UAB · Reto Deloitte Cyber. Un analista N1 virtual que tría la cola de Tarvia 24/7:
agrupa el ruido en patrones, investiga lo que se sale del patrón y deja a la persona solo las decisiones.

```
11.061 alertas  →  95 patrones (35 repetidos cubren 10.964)  →  10 atípicos + alertas únicas a investigar
```

## Cómo funciona

| # | Etapa | Quién | Fichero |
|---|---|---|---|
| 1 | Ingesta y huella: agrupa por patrón, marca atípicos | código | `core/fingerprint.py` |
| 2 | Pack de contexto: CMDB, usuario, RRHH, cambios, TI, logs ±24 h; aísla el texto no fiable | código | `core/context.py`, `core/tools.py` |
| 3 | Agente investigador: sigue el runbook, argumenta con evidencias | **LLM** | `agent/triage.py` |
| 4 | Motor de política: matriz de severidad, escalado, aprobaciones | código | `core/policy.py` |
| 5 | Correlación en incidentes | código | `core/correlate.py` (por hacer) |
| 6 | Consola: la persona aprueba, corrige y autoriza la contención | **persona** | `ui/`, `api/server.py` |

**Principio:** el LLM razona; el código decide lo que es regla escrita (matriz, escalado, aprobaciones).
Así es exacto, reproducible y no se puede manipular con un prompt injection.

## Puesta en marcha (10 minutos)

```bash
# 1. Datos de Deloitte dentro de data/
git clone https://github.com/acedo258/UAB_the_hack_deloitte_ganadores && cd UAB_the_hack_deloitte_ganadores
git clone https://github.com/dttdfr/DTT-UAB-The-Hack data/DTT-UAB-The-Hack

# 2. Python
pip install -r requirements.txt
python -m core.store                 # crea data/tarvia.duckdb (~10 s)
python -m pytest -q                  # 11 tests en verde

# 3. API simulada de Deloitte (contención y aprobaciones) — terminal aparte
cd data/DTT-UAB-The-Hack/06_herramientas && pip install -r requirements.txt && uvicorn mock_soc_api:app --port 8000

# 4. Nuestro backend — terminal aparte
LLM_MODEL=mock uvicorn api.server:app --port 8100 --reload

# 5. Consola — terminal aparte
cd ui && npm install && npm run dev  # http://localhost:5173
```

Probar el agente por consola: `python -m agent.triage ALR-20261020-011911` (añade `--deep` para el modo con herramientas).

### LLM
Cliente único compatible con OpenAI (`agent/llm.py`); se cambia con variables de entorno (ver `.env.example`).

| Uso | Modelo | Cómo |
|---|---|---|
| Sin LLM (UI, tests) | `mock` | `LLM_MODEL=mock` — heurística, **no es nuestro triaje** |
| Desarrollo | `qwen3:8b` en Ollama | `ollama pull qwen3:8b` · GPU de 8–12 GB |
| Triaje real y demo | `qwen/qwen3.8-27b` o `openai/gpt-oss-120b` en Groq | Gratis: ~30 peticiones/min, 8.000 tokens/min, 200.000/día por cuenta |

Con el plan gratuito de Groq caben ~20-30 triajes al día por cuenta: **cada uno crea la suya**, y todo se cachea en `data/cache/`.

## Estructura

```
core/
  config.py       variables de entorno
  schemas.py      CONTRATOS: ContextPack, Ticket, TraceStep, LLMTriage  ← no cambiar sin avisar
  store.py        DuckDB: una tabla por log + entity_events (índice de 2,6 M filas)
  tools.py        herramientas del agente (salida compacta + traza)
  context.py      construye el ContextPack y detecta texto no fiable
  policy.py       política del SOC en código
  fingerprint.py  huellas, patrones y atípicos
agent/
  llm.py          cliente LLM (Ollama / Groq / mock)
  triage.py       triaje rápido y modo investigador
  prompts/base.md prompt base (los runbooks se cargan del dataset)
api/server.py     FastAPI: cola, patrones, tickets, triaje en directo (SSE), decisiones, contención
ui/               Vue 3 + Vite + Pinia + Naive UI
eval/             gold.jsonl (casos etiquetados, NUNCA van al agente) + score.py
fixtures/         packs y tickets de ejemplo para trabajar sin backend
tests/            política y pruebas de humo sobre datos reales
docs/PLAN.md      plan paso a paso de cada persona
```

## Lo que no resolvemos (y lo decimos)
- Sin OSINT en directo por defecto: TIP interno + GeoIP + sandbox. Un indicador desconocido se marca como desconocido, no limpio.
- La correlación a semanas vista es heurística por entidades compartidas.
- La confianza del LLM no está calibrada estadísticamente; la medimos contra `eval/gold.jsonl`.
