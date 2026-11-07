<template>
  <n-space vertical :size="16">
    <n-alert type="info" :bordered="false">
      La IA tría un representante por patrón y la persona aprueba el patrón entero con una sola decisión.
      Los <b>atípicos</b> (huellas raras dentro de reglas ruidosas) van a investigación individual.
    </n-alert>
    <n-space align="center">
      <span>Mínimo de alertas por patrón</span>
      <n-input-number v-model:value="min" :min="1" style="width: 110px" @update:value="load" />
    </n-space>
    <n-data-table :columns="columns" :data="items" :loading="loading" :pagination="{ pageSize: 30 }"
                  :row-props="(r) => ({ style: 'cursor:pointer', onClick: () => $router.push(`/alerta/${r.sample_alert_id}`) })" />
  </n-space>
</template>

<script setup>
import { h, onMounted, ref } from 'vue'
import { NAlert, NDataTable, NInputNumber, NSpace, NTag } from 'naive-ui'
import { api, SEV_TYPE, VERDICT_LABEL } from '../api'

const items = ref([]), loading = ref(false), min = ref(1)
async function load() {
  loading.value = true
  try { items.value = await api.patterns(min.value) } finally { loading.value = false }
}
onMounted(load)

const tag = (t, type) => h(NTag, { size: 'small', type, bordered: false }, () => t)
const columns = [
  { title: 'Alertas', key: 'count', width: 90, sorter: (a, b) => a.count - b.count },
  { title: 'Regla', key: 'rule_id', width: 120 },
  { title: 'Huella', key: 'signature', ellipsis: { tooltip: true }, render: (r) => h('span', { class: 'mono' }, JSON.stringify(r.signature)) },
  { title: 'Tipo', key: 'is_outlier', width: 110, render: (r) => r.is_outlier ? tag('atípico', 'warning') : r.is_noise_candidate ? tag('repetido', 'default') : tag('único', 'info') },
  { title: 'Periodo', key: 'first', width: 170, render: (r) => `${r.first.slice(5, 10)} → ${r.last.slice(5, 10)}` },
  { title: 'Triaje del representante', key: 'ticket', width: 220,
    render: (r) => r.ticket ? tag(`${VERDICT_LABEL[r.ticket.verdict]} · ${r.ticket.severity}`, SEV_TYPE[r.ticket.severity]) : tag('sin triar', 'default') },
]
</script>
