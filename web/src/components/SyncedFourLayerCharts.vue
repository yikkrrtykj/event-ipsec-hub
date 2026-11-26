<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'
import { fmtTime, type MetricSample, type TimelineEvent } from '../api'

const props = defineProps<{
  samples: MetricSample[]
  events: TimelineEvent[]
}>()

const c1 = ref<HTMLElement | null>(null)
const c2 = ref<HTMLElement | null>(null)
const c3 = ref<HTMLElement | null>(null)
const c4 = ref<HTMLElement | null>(null)
const hovered = ref<MetricSample | null>(null)

let charts: echarts.ECharts[] = []

function causeLabel(code: string): string {
  const map: Record<string, string> = {
    VPN_HEALTHY_APP_SUSPECT: '链路正常',
    ISP_OUTER_DEGRADED: '公网线路异常',
    IPSEC_SA_EVENT: '隧道协商异常',
    TUNNEL_BLACKHOLE_OR_ASYMMETRIC: '隧道不通 / 路由异常',
    XFRM_CRYPTO_OR_MTU_DROP: '加解密 / MTU 异常',
    ACL_POLICY_DROP: '策略拦截',
    OBSERVATION_UNVERIFIED: '未检测'
  }
  return map[code] || code
}

function buildMarkLines(times: string[], samples: MetricSample[], events: TimelineEvent[]) {
  if (!samples.length || !events.length) return []
  const lines: any[] = []
  for (const ev of events) {
    let bestIdx = 0
    let bestDiff = Infinity
    for (let i = 0; i < samples.length; i++) {
      const diff = Math.abs(samples[i].ts_ms - ev.ts_ms)
      if (diff < bestDiff) {
        bestDiff = diff
        bestIdx = i
      }
    }
    const color =
      ev.severity === 'critical' ? '#ef4444' : ev.severity === 'warning' ? '#f59e0b' : '#38bdf8'
    lines.push({
      xAxis: times[bestIdx],
      lineStyle: { color, type: 'dashed', width: 1.5 },
      label: { formatter: ev.category, color, fontSize: 10 }
    })
  }
  return lines
}

function renderCharts() {
  if (charts.length !== 4) return
  const samples = props.samples || []
  const times = samples.map((s) => fmtTime(s.ts_ms))
  const markLines = buildMarkLines(times, samples, props.events || [])
  hovered.value = samples.length ? samples[samples.length - 1] : null

  const baseGrid = { left: 56, right: 54, top: 34, bottom: 26 }
  const axisLabel = { color: '#94a3b8', fontSize: 11 }
  const splitLine = { lineStyle: { color: '#1e293b' } }

  charts[0].setOption({
    backgroundColor: 'transparent',
    title: { text: '外层公网延迟与丢包', left: 10, top: 4, textStyle: { color: '#e2e8f0', fontSize: 12.5 } },
    tooltip: { trigger: 'axis', backgroundColor: '#0f172a', borderColor: '#334155', textStyle: { color: '#e2e8f0' } },
    grid: baseGrid,
    xAxis: { type: 'category', data: times, axisLabel, axisPointer: { show: true } },
    yAxis: [
      { type: 'value', name: 'RTT (ms)', nameTextStyle: axisLabel, axisLabel, splitLine },
      { type: 'value', name: '丢包 (%)', min: 0, max: 100, nameTextStyle: axisLabel, axisLabel, splitLine: { show: false } }
    ],
    series: [
      {
        name: '外层延迟 (ms)',
        type: 'line',
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#38bdf8' },
        data: samples.map((s) => Number(s.l1_outer_rtt_ms.toFixed(1))),
        markLine: { silent: true, symbol: 'none', data: markLines }
      },
      {
        name: '外层丢包 (%)',
        type: 'bar',
        yAxisIndex: 1,
        itemStyle: { color: 'rgba(239, 68, 68, 0.55)' },
        data: samples.map((s) => Number((s.l1_outer_loss * 100).toFixed(1)))
      }
    ]
  }, true)

  charts[1].setOption({
    backgroundColor: 'transparent',
    title: { text: 'IKE / IPsec 隧道状态', left: 10, top: 4, textStyle: { color: '#e2e8f0', fontSize: 12.5 } },
    tooltip: { trigger: 'axis', backgroundColor: '#0f172a', borderColor: '#334155', textStyle: { color: '#e2e8f0' } },
    grid: baseGrid,
    xAxis: { type: 'category', data: times, axisLabel, axisPointer: { show: true } },
    yAxis: {
      type: 'value',
      min: -1,
      max: 1,
      interval: 1,
      axisLabel: {
        color: '#94a3b8',
        fontSize: 11,
        formatter: (v: number) => (v === 1 ? '在线' : v === 0 ? '断开' : '未知')
      },
      splitLine
    },
    series: [
      {
        name: 'IKE SA',
        type: 'line',
        step: 'end',
        showSymbol: false,
        lineStyle: { width: 2.2 },
        itemStyle: { color: '#22c55e' },
        data: samples.map((s) => s.l2_ike_state),
        markLine: { silent: true, symbol: 'none', data: markLines }
      },
      {
        name: 'IPsec SA',
        type: 'line',
        step: 'end',
        showSymbol: false,
        lineStyle: { width: 2, type: 'dashed' },
        itemStyle: { color: '#a855f7' },
        data: samples.map((s) => s.l2_child_state)
      }
    ]
  }, true)

  charts[2].setOption({
    backgroundColor: 'transparent',
    title: { text: '通道带宽与异常计数', left: 10, top: 4, textStyle: { color: '#e2e8f0', fontSize: 12.5 } },
    tooltip: { trigger: 'axis', backgroundColor: '#0f172a', borderColor: '#334155', textStyle: { color: '#e2e8f0' } },
    grid: baseGrid,
    xAxis: { type: 'category', data: times, axisLabel, axisPointer: { show: true } },
    yAxis: [
      { type: 'value', name: '带宽 (Mbps)', nameTextStyle: axisLabel, axisLabel, splitLine },
      { type: 'value', name: '异常数', minInterval: 1, nameTextStyle: axisLabel, axisLabel, splitLine: { show: false } }
    ],
    series: [
      {
        name: '入带宽 (Mbps)',
        type: 'line',
        smooth: true,
        showSymbol: false,
        areaStyle: { opacity: 0.14 },
        itemStyle: { color: '#10b981' },
        data: samples.map((s) => Number((s.l3_rx_bps / 1_000_000).toFixed(2))),
        markLine: { silent: true, symbol: 'none', data: markLines }
      },
      {
        name: '出带宽 (Mbps)',
        type: 'line',
        smooth: true,
        showSymbol: false,
        areaStyle: { opacity: 0.12 },
        itemStyle: { color: '#60a5fa' },
        data: samples.map((s) => Number((s.l3_tx_bps / 1_000_000).toFixed(2)))
      },
      {
        name: 'XFRM 错误 / 策略拦截',
        type: 'bar',
        yAxisIndex: 1,
        itemStyle: { color: '#f59e0b' },
        data: samples.map((s) => s.l3_xfrm_err_delta + s.l3_nft_drop_delta)
      }
    ]
  }, true)

  charts[3].setOption({
    backgroundColor: 'transparent',
    title: { text: '内网端到端探针', left: 10, top: 4, textStyle: { color: '#e2e8f0', fontSize: 12.5 } },
    tooltip: { trigger: 'axis', backgroundColor: '#0f172a', borderColor: '#334155', textStyle: { color: '#e2e8f0' } },
    grid: baseGrid,
    xAxis: { type: 'category', data: times, axisLabel, axisPointer: { show: true } },
    yAxis: [
      { type: 'value', name: 'RTT (ms)', nameTextStyle: axisLabel, axisLabel, splitLine },
      { type: 'value', name: '丢包 (%)', min: 0, max: 100, nameTextStyle: axisLabel, axisLabel, splitLine: { show: false } }
    ],
    series: [
      {
        name: 'UDP 延迟 (ms)',
        type: 'line',
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#34d399' },
        data: samples.map((s) => Number(s.l4_udp_rtt_ms.toFixed(1))),
        markLine: { silent: true, symbol: 'none', data: markLines }
      },
      {
        name: 'UDP P95 (ms)',
        type: 'line',
        smooth: true,
        showSymbol: false,
        lineStyle: { type: 'dotted' },
        itemStyle: { color: '#fbbf24' },
        data: samples.map((s) => Number(s.l4_udp_p95_ms.toFixed(1)))
      },
      {
        name: 'UDP 丢包 (%)',
        type: 'bar',
        yAxisIndex: 1,
        itemStyle: { color: 'rgba(239, 68, 68, 0.65)' },
        data: samples.map((s) => Number((s.l4_udp_loss * 100).toFixed(1)))
      }
    ]
  }, true)
}

function handleResize() {
  for (const ch of charts) ch.resize()
}

onMounted(() => {
  const els = [c1.value, c2.value, c3.value, c4.value]
  charts = els.map((el) => {
    const inst = echarts.init(el!)
    inst.group = 'sync-diag'
    inst.on('updateAxisPointer', (ev: any) => {
      const idx = ev?.axesInfo?.[0]?.value
      if (typeof idx === 'number' && props.samples[idx]) {
        hovered.value = props.samples[idx]
      }
    })
    return inst
  })
  echarts.connect('sync-diag')
  renderCharts()
  window.addEventListener('resize', handleResize)
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', handleResize)
  echarts.disconnect('sync-diag')
  for (const ch of charts) ch.dispose()
})

watch(() => [props.samples, props.events], renderCharts, { deep: true })

function stText(v: number) {
  if (v === 1) return '在线'
  if (v === 0) return '断开'
  return '未检测'
}
</script>

<template>
  <div>
    <div v-if="hovered" class="card" style="padding: 12px 16px; border-color: #3b82f6;">
      <div class="row">
        <strong>{{ fmtTime(hovered.ts_ms) }}</strong>
        <span class="pill" :class="hovered.root_cause === 'VPN_HEALTHY_APP_SUSPECT' ? 'pill-ok' : hovered.root_cause === 'OBSERVATION_UNVERIFIED' ? 'pill-unknown' : 'pill-critical'">
          {{ causeLabel(hovered.root_cause) }}
        </span>
        <span class="muted">外层 {{ hovered.l1_outer_rtt_ms.toFixed(1) }}ms / 丢包{{ (hovered.l1_outer_loss*100).toFixed(0) }}%</span>
        <span class="muted">IKE {{ stText(hovered.l2_ike_state) }} · IPsec {{ stText(hovered.l2_child_state) }}</span>
        <span class="muted">带宽 入 {{ (hovered.l3_rx_bps/1e6).toFixed(2) }} / 出 {{ (hovered.l3_tx_bps/1e6).toFixed(2) }} Mbps</span>
        <span class="muted">探针 {{ hovered.l4_udp_rtt_ms.toFixed(1) }}ms / 丢包{{ (hovered.l4_udp_loss*100).toFixed(0) }}%</span>
      </div>
      <div style="margin-top: 6px; font-size: 13px; color: #f8fafc;">
        {{ hovered.root_detail }}
      </div>
    </div>

    <div class="card" style="padding: 10px 8px;">
      <div ref="c1" style="width: 100%; height: 175px;"></div>
      <div ref="c2" style="width: 100%; height: 155px;"></div>
      <div ref="c3" style="width: 100%; height: 175px;"></div>
      <div ref="c4" style="width: 100%; height: 175px;"></div>
    </div>
  </div>
</template>
