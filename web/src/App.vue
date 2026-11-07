<template>
  <n-config-provider :theme-overrides="theme">
    <n-message-provider>
      <n-layout style="min-height: 100vh">
        <n-layout-header bordered class="header">
          <div class="brand">SOC N1 · Tarvia <span class="sub">triaje asistido por IA</span></div>
          <n-menu mode="horizontal" :options="menu" :value="$route.path" @update:value="(k) => $router.push(k)" />
          <div v-if="stats.data" class="funnel">
            <span><b>{{ fmt(stats.data.alerts) }}</b> alertas</span><span class="arrow">→</span>
            <span><b>{{ stats.data.patterns }}</b> patrones</span><span class="arrow">→</span>
            <span><b>{{ stats.data.outliers }}</b> atípicos a investigar</span>
          </div>
        </n-layout-header>
        <n-layout-content content-style="padding: 20px 24px">
          <router-view />
        </n-layout-content>
      </n-layout>
    </n-message-provider>
  </n-config-provider>
</template>

<script setup>
import { onMounted } from 'vue'
import { NConfigProvider, NMessageProvider, NLayout, NLayoutHeader, NLayoutContent, NMenu } from 'naive-ui'
import { useStats } from './stores/stats'

const stats = useStats()
onMounted(() => stats.load())
const fmt = (n) => n.toLocaleString('es-ES')
const menu = [
  { label: 'Cola de alertas', key: '/' },
  { label: 'Patrones', key: '/patrones' },
]
// Verde corporativo del reto; la IA en morado, la persona en verde (ver style.css)
const theme = { common: { primaryColor: '#0F6E56', primaryColorHover: '#1D9E75', primaryColorPressed: '#085041' } }
</script>

<style>
body { margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: #f7f7f5; }
.header { display: flex; align-items: center; gap: 24px; padding: 0 24px; height: 56px; }
.brand { font-weight: 600; white-space: nowrap; }
.brand .sub { font-weight: 400; color: #777; margin-left: 6px; font-size: 13px; }
.funnel { margin-left: auto; display: flex; gap: 8px; font-size: 13px; color: #444; white-space: nowrap; }
.funnel .arrow { color: #aaa; }
.ai { border-left: 3px solid #7F77DD; }
.human { border-left: 3px solid #1D9E75; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
</style>
