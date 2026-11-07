<template>
  <n-space vertical :size="16">
    <!-- Selector de incidentes -->
    <n-card size="small" class="incident-header-card">
      <n-space align="center" justify="space-between" style="flex-wrap: wrap;">
        <n-space align="center" :size="12">
          <span style="font-weight: 600;">Seleccionar Incidente Correlacionado:</span>
          <n-select
            v-model:value="selectedIncidentId"
            :options="incidentOptions"
            style="width: 440px;"
            @update:value="onSelectIncident"
          />
        </n-space>

        <n-space v-if="currentIncident" align="center" :size="8">
          <n-tag :type="currentIncident.severity === 'critical' ? 'error' : 'warning'" size="medium">
            Severidad: {{ currentIncident.severity?.toUpperCase() }}
          </n-tag>
          <n-tag type="info" size="medium">
            Estado: {{ currentIncident.status?.toUpperCase() }}
          </n-tag>
          <n-tag size="medium">
            Entidad clave: {{ currentIncident.primary_entity }}
          </n-tag>
        </n-space>
      </n-space>
    </n-card>

    <div v-if="currentIncident">
      <n-grid :cols="24" :x-gap="16" :y-gap="16">
        <!-- Columna Izquierda: Línea temporal de la Cadena de Ataque (Kill Chain) -->
        <n-gi :span="9">
          <n-card title="⛓️ Cadena de Ataque (Kill Chain Timeline)" size="small" style="height: 600px; overflow-y: auto;">
            <p style="margin: 0 0 12px 0; color: #475569; font-size: 13px; line-height: 1.5;">
              {{ currentIncident.impact_summary }}
            </p>
            <n-divider style="margin: 8px 0 16px 0;" />
            <n-timeline>
              <n-timeline-item
                v-for="(t, idx) in currentIncident.timeline"
                :key="idx"
                type="error"
                :title="`[${t.phase}] ${t.event}`"
                :time="t.ts"
              />
            </n-timeline>

            <n-divider title-placement="left" style="margin: 20px 0 12px 0;">Alertas correlacionadas</n-divider>
            <n-space :size="6" style="flex-wrap: wrap;">
              <n-button
                v-for="aid in currentIncident.alerts"
                :key="aid"
                size="tiny"
                secondary
                type="primary"
                class="mono"
                @click="$router.push(`/alerta/${aid}`)"
              >
                {{ aid }}
              </n-button>
            </n-space>
          </n-card>
        </n-gi>

        <!-- Columna Derecha: Grafo de Entidades Cytoscape.js -->
        <n-gi :span="15">
          <n-card title="🕸️ Grafo de Entidades e Infraestructura Maliciosa (Cytoscape.js)" size="small" style="height: 600px;">
            <template #header-extra>
              <n-space :size="8" align="center">
                <n-tag size="tiny" type="error">C2 / Malicioso</n-tag>
                <n-tag size="tiny" type="warning">Endpoint Afectado</n-tag>
                <n-tag size="tiny" type="info">Identidad</n-tag>
                <n-tag size="tiny">Fichero / Proceso</n-tag>
                <n-button size="tiny" secondary type="primary" @click="fitGraph">
                  🎯 Centrar grafo
                </n-button>
                <n-button size="tiny" secondary @click="reLayout">
                  🔄 Reordenar
                </n-button>
              </n-space>
            </template>
            <div ref="cyContainer" class="cytoscape-box"></div>
          </n-card>
        </n-gi>
      </n-grid>
    </div>
  </n-space>
</template>

<script setup>
import { computed, nextTick, onMounted, ref } from 'vue'
import { NButton, NCard, NDivider, NGi, NGrid, NSelect, NSpace, NTag, NTimeline, NTimelineItem, useMessage } from 'naive-ui'
import cytoscape from 'cytoscape'
import { api } from '../api'

const msg = useMessage()
const incidents = ref([])
const selectedIncidentId = ref(null)
const cyContainer = ref(null)
let cyInstance = null

onMounted(async () => {
  try {
    incidents.value = await api.incidents()
    if (incidents.value.length > 0) {
      selectedIncidentId.value = incidents.value[0].incident_id
      await nextTick()
      renderGraph(incidents.value[0])
    }
  } catch (err) {
    msg.error('Error cargando incidentes: ' + err.message)
  }
})

const incidentOptions = computed(() =>
  incidents.value.map((i) => ({
    label: `${i.incident_id} · ${i.title}`,
    value: i.incident_id,
  }))
)

const currentIncident = computed(() =>
  incidents.value.find((i) => i.incident_id === selectedIncidentId.value)
)

function onSelectIncident(val) {
  const inc = incidents.value.find((i) => i.incident_id === val)
  if (inc) {
    nextTick(() => renderGraph(inc))
  }
}

function renderGraph(incident) {
  if (!cyContainer.value) return
  if (cyInstance) {
    cyInstance.destroy()
  }

  const elements = [
    ...(incident.nodes || []).map((n) => ({
      data: {
        id: n.id,
        label: n.label,
        type: n.type,
      },
    })),
    ...(incident.edges || []).map((e) => ({
      data: {
        source: e.source,
        target: e.target,
        label: e.label,
      },
    })),
  ]

  cyInstance = cytoscape({
    container: cyContainer.value,
    elements,
    style: [
      // Estilo base de nodos
      {
        selector: 'node',
        style: {
          'background-color': '#0ea5e9',
          label: 'data(label)',
          color: '#0f172a',
          'font-size': '11px',
          'font-weight': 600,
          'font-family': 'system-ui, -apple-system, sans-serif',
          'text-valign': 'bottom',
          'text-margin-y': 7,
          'text-max-width': '110px',
          'text-wrap': 'wrap',
          'text-background-color': '#ffffff',
          'text-background-opacity': 0.92,
          'text-background-padding': '3px',
          'text-background-shape': 'roundrectangle',
          'border-width': 2,
          'border-color': '#ffffff',
          width: 38,
          height: 38,
        },
      },
      // C2 / IP Maliciosa
      {
        selector: 'node[type = "c2"], node[type = "ip"]',
        style: {
          'background-color': '#dc2626',
          shape: 'diamond',
          width: 44,
          height: 44,
        },
      },
      // Host / Servidor objetivo
      {
        selector: 'node[type = "host"], node[type = "target"]',
        style: {
          'background-color': '#d97706',
          shape: 'round-rectangle',
          width: 44,
          height: 34,
        },
      },
      // Fichero / Payload
      {
        selector: 'node[type = "file"]',
        style: {
          'background-color': '#7c3aed',
          shape: 'round-rectangle',
          width: 38,
          height: 32,
        },
      },
      // Usuario / Identidad
      {
        selector: 'node[type = "user"]',
        style: {
          'background-color': '#0284c7',
          shape: 'ellipse',
        },
      },
      // Regla / Servicio
      {
        selector: 'node[type = "rule"], node[type = "service"]',
        style: {
          'background-color': '#475569',
          shape: 'hexagon',
          width: 40,
          height: 36,
        },
      },
      // Aristas / Conexiones
      {
        selector: 'edge',
        style: {
          width: 2.5,
          'line-color': '#94a3b8',
          'target-arrow-color': '#64748b',
          'target-arrow-shape': 'triangle',
          'arrow-scale': 1.2,
          'curve-style': 'bezier',
          label: 'data(label)',
          'font-size': '10px',
          'font-weight': 500,
          color: '#334155',
          'text-background-color': '#ffffff',
          'text-background-opacity': 0.92,
          'text-background-padding': '2px',
          'text-background-shape': 'roundrectangle',
        },
      },
    ],
    layout: {
      name: 'cose',
      animate: false,
      padding: 40,
      nodeRepulsion: 35000,
      idealEdgeLength: 150,
      edgeElasticity: 60,
      nestingFactor: 1.2,
      gravity: 0.15,
      numIter: 1000,
    },
  })

  // Ajuste inicial suave
  cyInstance.fit(undefined, 40)
}

function fitGraph() {
  if (cyInstance) cyInstance.fit(undefined, 40)
}

function reLayout() {
  if (cyInstance) {
    cyInstance.layout({
      name: 'cose',
      animate: true,
      animationDuration: 500,
      padding: 40,
      nodeRepulsion: 35000,
      idealEdgeLength: 150,
    }).run()
  }
}
</script>

<style scoped>
.incident-header-card {
  border-radius: 8px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
}
.cytoscape-box {
  width: 100%;
  height: 520px;
  background: #f8fafc;
  border-radius: 6px;
  border: 1px solid #e2e8f0;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
</style>
