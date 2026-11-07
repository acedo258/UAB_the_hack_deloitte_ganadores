// Todas las llamadas al backend en un solo sitio.
const j = async (r) => {
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText)
  return r.json()
}
export const api = {
  stats: () => fetch('/api/stats').then(j),
  queue: (p = {}) => fetch('/api/queue?' + new URLSearchParams(p)).then(j),
  alert: (id) => fetch(`/api/alerts/${id}`).then(j),
  ticket: (id) => fetch(`/api/tickets/${id}`).then((r) => (r.status === 404 ? null : j(r))),
  event: (id) => fetch(`/api/events/${id}`).then(j),
  patterns: (min = 1) => fetch(`/api/patterns?min_count=${min}`).then(j),
  decide: (body) => fetch('/api/decisions', post(body)).then(j),
  contain: (body) => fetch('/api/containment', post(body)).then(j),
  // Triaje en directo: onStep(TraceStep) por cada paso, onTicket(Ticket) al final
  triage(id, { deep = false, force = false, onStep, onTicket, onError }) {
    const es = new EventSource(`/api/triage/${id}/stream?deep=${deep}&force=${force}`)
    es.addEventListener('step', (e) => onStep?.(JSON.parse(e.data)))
    es.addEventListener('ticket', (e) => { onTicket?.(JSON.parse(e.data)); es.close() })
    es.addEventListener('error', (e) => { onError?.(e.data ? JSON.parse(e.data).detail : 'conexión cerrada'); es.close() })
    return es
  },
}
const post = (body) => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })

export const SEV_TYPE = { informational: 'default', low: 'info', medium: 'warning', high: 'error', critical: 'error' }
export const VERDICT_LABEL = {
  true_positive: 'Verdadero positivo', benign_true_positive: 'Autorizado (benigno)',
  false_positive: 'Falso positivo', needs_more_info: 'Necesita revisión',
}
