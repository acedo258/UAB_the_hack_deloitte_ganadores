<template>
  <n-space vertical :size="16">
    <n-alert type="info" :bordered="false" class="info-banner">
      <b>Agrupación inteligente de patrones:</b> La IA tría una sola alerta representativa por patrón y el analista humano puede
      <b>aprobar o descartar el patrón entero con una sola decisión</b> (resolviendo cientos de alertas en un clic).
      Los <b>atípicos</b> (anomalías dentro de reglas comunes) se desvían a investigación individual.
    </n-alert>

    <n-card size="small">
      <n-space align="center" justify="space-between">
        <n-space align="center" :size="12">
          <span>Mínimo de alertas por patrón:</span>
          <n-input-number v-model:value="min" :min="1" style="width: 110px" @update:value="load" />
          <n-button secondary type="primary" :loading="loading" @click="load">Recargar</n-button>
        </n-space>

        <n-space align="center" :size="12">
          <n-tag type="info" size="medium" :bordered="false">
            <b>{{ items.length }}</b> patrones detectados
          </n-tag>
          <n-tag type="success" size="medium" :bordered="false">
            <b>{{ totalAlertsCovered }}</b> alertas cubiertas
          </n-tag>
        </n-space>
      </n-space>
    </n-card>

    <n-data-table
      :columns="columns"
      :data="items"
      :loading="loading"
      :pagination="{ pageSize: 25 }"
      :row-props="(r) => ({ style: 'cursor: pointer;', onClick: () => $router.push(`/alerta/${r.sample_alert_id}`) })"
    />

    <!-- Modal de confirmación para aprobación en bloque -->
    <n-modal v-model:show="showApproveModal" preset="dialog" title="Aprobar patrón en bloque">
      <template #default>
        <p v-if="selectedPattern">
          ¿Deseas aprobar en bloque las <b>{{ selectedPattern.count }}</b> alertas asociadas a este patrón?
        </p>
        <div style="margin: 12px 0;">
          <label style="font-size: 13px; font-weight: 500; display: block; margin-bottom: 4px;">Nombre del analista responsable:</label>
          <n-input v-model:value="analystName" placeholder="Escribe tu nombre / alias para auditoría" />
        </div>
      </template>
      <template #action>
        <n-button @click="showApproveModal = false">Cancelar</n-button>
        <n-button type="primary" :loading="approving" @click="confirmApprovePattern">
          Confirmar y aprobar {{ selectedPattern?.count }} alertas
        </n-button>
      </template>
    </n-modal>
  </n-space>
</template>

<script setup>
import { computed, h, onMounted, ref } from 'vue'
import { NAlert, NButton, NCard, NDataTable, NInput, NInputNumber, NModal, NSpace, NTag, useMessage } from 'naive-ui'
import { api, SEV_TYPE, VERDICT_LABEL } from '../api'

const msg = useMessage()
const items = ref([])
const loading = ref(false)
const min = ref(1)

const showApproveModal = ref(false)
const selectedPattern = ref(null)
const analystName = ref('')
const approving = ref(false)

async function load() {
  loading.value = true
  try {
    items.value = await api.patterns(min.value)
  } finally {
    loading.value = false
  }
}
onMounted(load)

const totalAlertsCovered = computed(() => items.value.reduce((acc, p) => acc + (p.count || 0), 0))

function openApproveModal(e, pattern) {
  e.stopPropagation()
  selectedPattern.value = pattern
  showApproveModal.value = true
}

async function confirmApprovePattern() {
  if (!analystName.value) {
    return msg.warning('Escribe tu nombre para dejar constancia en la auditoría')
  }
  approving.value = true
  try {
    await api.decide({
      alert_id: selectedPattern.value.sample_alert_id,
      decision: 'approve',
      analyst: analystName.value,
      apply_to_pattern: true,
    })
    msg.success(`Patrón aprobado con éxito. ${selectedPattern.value.count} alertas resueltas.`)
    showApproveModal.value = false
    await load()
  } catch (err) {
    msg.error(err.message || 'Error al aprobar el patrón')
  } finally {
    approving.value = false
  }
}

const tag = (t, type) => h(NTag, { size: 'small', type, bordered: false }, () => t)

const columns = [
  {
    title: 'Volumen',
    key: 'count',
    width: 105,
    sorter: (a, b) => b.count - a.count,
    render: (r) => h('b', { style: 'font-size: 14px; color: #0F6E56;' }, `×${r.count}`),
  },
  { title: 'Regla SIEM', key: 'rule_id', width: 130, render: (r) => h('span', { class: 'mono' }, r.rule_id) },
  {
    title: 'Huella digital (Signature)',
    key: 'signature',
    ellipsis: { tooltip: true },
    render: (r) => h('span', { class: 'mono', style: 'color: #334155; font-size: 12px;' }, JSON.stringify(r.signature)),
  },
  {
    title: 'Clasificación',
    key: 'is_outlier',
    width: 120,
    render: (r) =>
      r.is_outlier
        ? tag('⚠️ Atípico', 'warning')
        : r.is_noise_candidate
        ? tag('🔁 Repetido', 'default')
        : tag('⚡ Único', 'info'),
  },
  {
    title: 'Periodo temporal',
    key: 'first',
    width: 170,
    render: (r) => h('span', { class: 'mono', style: 'font-size: 12px;' }, `${r.first?.slice(5, 10)} → ${r.last?.slice(5, 10)}`),
  },
  {
    title: 'Veredicto de muestra',
    key: 'ticket',
    width: 200,
    render: (r) => {
      if (!r.ticket) return tag('⏳ Sin triar', 'default')
      const label = VERDICT_LABEL[r.ticket.verdict] || r.ticket.verdict
      return tag(`${label} (${r.ticket.severity})`, SEV_TYPE[r.ticket.severity])
    },
  },
  {
    title: 'Acción en bloque',
    key: 'actions',
    width: 160,
    render: (r) => {
      if (r.is_outlier) {
        return h(NTag, { size: 'tiny', type: 'warning' }, () => 'Revisión individual')
      }
      return h(
        NButton,
        {
          size: 'tiny',
          type: 'primary',
          secondary: true,
          onClick: (e) => openApproveModal(e, r),
        },
        () => `Aprobar (×${r.count})`
      )
    },
  },
]
</script>

<style scoped>
.info-banner {
  border-radius: 8px;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
</style>