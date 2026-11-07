<template>
  <n-space vertical :size="16">
    <!-- Barra superior de filtros -->
    <n-card size="small" class="filter-card">
      <n-space align="center" justify="space-between" style="flex-wrap: wrap;">
        <n-space align="center" :size="16">
          <n-switch v-model:value="filters.dev" @update:value="load">
            <template #checked>Muestra desarrollo (150)</template>
            <template #unchecked>Todas las alertas (11.061)</template>
          </n-switch>
          <n-switch v-model:value="filters.outliers_only" @update:value="load">
            <template #checked>Solo atípicos</template>
            <template #unchecked>Todos los tipos</template>
          </n-switch>
          <n-input
            v-model:value="filters.rule_id"
            placeholder="Filtrar por regla (ej. UC-EDR-001)"
            clearable
            style="width: 230px"
            @change="load"
          />
          <n-select
            v-model:value="statusFilter"
            :options="statusOptions"
            placeholder="Filtrar por estado"
            style="width: 190px"
          />
          <n-button secondary type="primary" :loading="loading" @click="load">
            🔄 Recargar
          </n-button>
        </n-space>

        <n-space align="center" :size="12">
          <n-tag type="info" size="medium" :bordered="false">
            <b>{{ filteredItems.length }}</b> de <b>{{ total }}</b> alertas
          </n-tag>
          <n-tag v-if="nightCount > 0" type="warning" size="medium" :bordered="false">
            🌙 {{ nightCount }} fuera de horario (24/7)
          </n-tag>
        </n-space>
      </n-space>
    </n-card>

    <!-- Tabla priorizada de alertas -->
    <n-data-table
      :columns="columns"
      :data="filteredItems"
      :loading="loading"
      :pagination="{ pageSize: 25, showSizePicker: true, pageSizes: [25, 50, 100] }"
      :row-props="(r) => ({ style: 'cursor: pointer;', onClick: () => $router.push(`/alerta/${r.alert_id}`) })"
    />
  </n-space>
</template>

<script setup>
import { computed, h, onMounted, reactive, ref } from 'vue'
import { NButton, NCard, NDataTable, NInput, NSelect, NSpace, NSwitch, NTag, NTooltip } from 'naive-ui'
import { api, SEV_TYPE, VERDICT_LABEL } from '../api'

const filters = reactive({ dev: true, outliers_only: false, rule_id: '' })
const statusFilter = ref('all')
const items = ref([])
const total = ref(0)
const loading = ref(false)

const SEV_WEIGHT = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 }
const SLA_HOURS = { critical: 0.25, high: 0.5, medium: 4, low: 24, informational: 24 }

const statusOptions = [
  { label: 'Todos los estados', value: 'all' },
  { label: '⏳ Sin triar', value: 'pending' },
  { label: '🤖 Propuesto por IA', value: 'proposed' },
  { label: '✅ Aprobado N2', value: 'approved' },
  { label: '✏️ Corregido', value: 'corrected' },
  { label: '🚨 Escalado', value: 'escalated' },
  { label: '⚠️ Con manipulación', value: 'manipulation' },
]

// Cálculo de si una alerta ocurrió fuera de horario laboral de oficina (08:00 - 18:00 L-V)
function isOutOfHours(isoString) {
  if (!isoString) return false
  const d = new Date(isoString)
  const day = d.getUTCDay() // 0 = Domingo, 6 = Sábado
  if (day === 0 || day === 6) return true
  // En octubre en Madrid es UTC+2, por lo que 08:00-18:00 local es aprox 06:00-16:00 UTC
  const hour = d.getUTCHours()
  return hour < 6 || hour >= 16
}

// Cálculo del estado del SLA
function getSlaInfo(row) {
  const sev = row.ticket?.severity || row.severity || 'low'
  const limitHours = SLA_HOURS[sev] || 24
  const created = new Date(row.created_at).getTime()
  const deadline = created + limitHours * 3600 * 1000
  
  // Si ya fue decidido por un humano
  if (row.ticket && ['approved', 'corrected', 'escalated'].includes(row.ticket.status)) {
    return { status: 'resolved', text: 'Resuelto', type: 'success' }
  }

  // Alerta histórica o actual en cola: calcular tiempo relativo
  const now = new Date('2026-10-25T12:00:00Z').getTime() // Ancla temporal del dataset
  const diffMinutes = Math.round((deadline - now) / 60000)

  if (diffMinutes < 0) {
    return { status: 'breached', text: `Vencido (${Math.abs(Math.round(diffMinutes / 60))}h)`, type: 'error' }
  }
  if (diffMinutes < 60) {
    return { status: 'urgent', text: `${diffMinutes} min`, type: 'warning' }
  }
  return { status: 'ok', text: `${Math.round(diffMinutes / 60)}h restantes`, type: 'default' }
}

async function load() {
  loading.value = true
  try {
    const r = await api.queue({ ...filters, limit: 2000 })
    items.value = r.items || []
    total.value = r.total || 0
  } finally {
    loading.value = false
  }
}
onMounted(load)

// Conteo de alertas fuera de horario
const nightCount = computed(() => items.value.filter((r) => isOutOfHours(r.created_at)).length)

// Elementos filtrados y ordenados por severidad y prioridad de atención
const filteredItems = computed(() => {
  let list = [...items.value]

  if (statusFilter.value === 'pending') {
    list = list.filter((r) => !r.ticket)
  } else if (statusFilter.value === 'proposed') {
    list = list.filter((r) => r.ticket?.status === 'proposed')
  } else if (statusFilter.value === 'approved') {
    list = list.filter((r) => r.ticket?.status === 'approved')
  } else if (statusFilter.value === 'corrected') {
    list = list.filter((r) => r.ticket?.status === 'corrected')
  } else if (statusFilter.value === 'escalated') {
    list = list.filter((r) => r.ticket?.status === 'escalated' || r.ticket?.escalate)
  } else if (statusFilter.value === 'manipulation') {
    list = list.filter((r) => r.ticket?.manipulation_attempt)
  }

  // Ordenar: Alertas con intento de manipulación primero, luego por severidad final descendente, luego atípicos
  list.sort((a, b) => {
    if (a.ticket?.manipulation_attempt && !b.ticket?.manipulation_attempt) return -1
    if (!a.ticket?.manipulation_attempt && b.ticket?.manipulation_attempt) return 1

    const sevA = SEV_WEIGHT[a.ticket?.severity || a.severity] || 0
    const sevB = SEV_WEIGHT[b.ticket?.severity || b.severity] || 0
    if (sevB !== sevA) return sevB - sevA

    if (a.is_outlier && !b.is_outlier) return -1
    if (!a.is_outlier && b.is_outlier) return 1

    return new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  })

  return list
})

const tag = (text, type, bordered = false) => h(NTag, { size: 'small', type, bordered }, () => text)

const columns = [
  {
    title: 'Fecha / Horario',
    key: 'created_at',
    width: 170,
    render: (r) => {
      const dateStr = r.created_at.slice(0, 16).replace('T', ' ')
      const outOfHours = isOutOfHours(r.created_at)
      return h('div', { style: 'display: flex; flex-direction: column; gap: 2px;' }, [
        h('span', { class: 'mono', style: 'font-size: 12px;' }, dateStr),
        outOfHours
          ? h(NTag, { size: 'tiny', type: 'warning', bordered: false, style: 'width: fit-content;' }, () => '🌙 24/7 Nocturna')
          : null,
      ])
    },
  },
  { title: 'Regla', key: 'rule_id', width: 125, render: (r) => h('span', { class: 'mono' }, r.rule_id) },
  { title: 'Qué saltó', key: 'rule_name', ellipsis: { tooltip: true } },
  {
    title: 'Severidad',
    key: 'severity',
    width: 110,
    render: (r) => {
      const finalSev = r.ticket?.severity || r.severity
      return tag(finalSev?.toUpperCase(), SEV_TYPE[finalSev])
    },
  },
  {
    title: 'Patrón',
    key: 'pattern_count',
    width: 120,
    render: (r) =>
      r.is_outlier
        ? tag('⚠️ atípico', 'warning')
        : tag(`🔁 ×${r.pattern_count || 1}`, 'default'),
  },
  {
    title: 'Veredicto IA',
    key: 'ticket',
    width: 170,
    render: (r) => {
      if (!r.ticket) return tag('⏳ sin triar', 'default')
      const verdict = r.ticket.verdict
      const isTp = verdict === 'true_positive'
      const isFp = verdict === 'false_positive'
      const label = VERDICT_LABEL[verdict] || verdict
      return tag(label, isTp ? 'error' : (isFp ? 'success' : 'warning'))
    },
  },
  {
    title: 'SLA Objetivo',
    key: 'sla',
    width: 130,
    render: (r) => {
      const sla = getSlaInfo(r)
      return tag(sla.text, sla.type)
    },
  },
  {
    title: 'Estado',
    key: 'status',
    width: 130,
    render: (r) => {
      if (!r.ticket) return tag('pendiente', 'default')
      if (r.ticket.manipulation_attempt) {
        return tag('🚨 Manipulación', 'error')
      }
      const st = r.ticket.status || 'proposed'
      const typeMap = { proposed: 'info', approved: 'success', corrected: 'warning', escalated: 'error' }
      return tag(st.toUpperCase(), typeMap[st] || 'default')
    },
  },
]
</script>

<style scoped>
.filter-card {
  border-radius: 8px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
}
.muted {
  color: #64748b;
  font-size: 13px;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
</style>