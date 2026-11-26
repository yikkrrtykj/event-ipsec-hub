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

function buildMarkLines(times: string[], samples: MetricSample[], events: TimelineEvent[]) {
  if (!samples.length || !events.length) return []
  const lines: any[] = []
  for (const ev of events) {
    // Snap event to nearest sample index on the shared X axis
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
      label: {
        formatter: ev.category,
        color,
        fontSize: 10,
        rotate: 0
      }
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

  // Layer 1: Outer WAN / ISP Quality
  charts[0].setOption({
    backgroundColor: 'transparent',
    title: { text: 'L1 · 公网外层 / ISP 质量 (RTT ms & 丢包 %)', left: 10, top: 4, textStyle: { color: '#e2e8f0', fontSize: 12.5 } },
    tooltip: { trigger: 'axis', backgroundColor: '#0f172a', borderColor: '#334155', textStyle: { color: '#e2e8f0' } },
    grid: baseGrid,
    xAxis: { type: 'category', data: times, axisLabel, axisPointer: { show: true } },
    yAxis: [
      { type: 'value', name: 'RTT(ms)', nameTextStyle: axisLabel, axisLabel, splitLine },
      { type: 'value', name: '丢包%', min: 0, max: 100, nameTextStyle: axisLabel, axisLabel, splitLine: { show: false } }
    ],
    series: [
      {
        name: '外层 RTT(ms)',
        type: 'line',
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#38bdf8' },
        data: samples.map((s) => Number(s.l1_outer_rtt_ms.toFixed(1))),
        markLine: { silent: true, symbol: 'none', data: markLines }
      },
      {
        name: '外层丢包%',
        type: 'bar',
        yAxisIndex: 1,
        itemStyle: { color: 'rgba(239, 68, 68, 0.55)' },
        data: samples.map((s) => Number((s.l1_outer_loss * 100).toFixed(1)))
      }
    ]
  }, true)

  // Layer 2: IPsec Control Plane (IKE / CHILD SA)
  charts[1].setOption({
    backgroundColor: 'transparent',
    title: { text: 'L2 · IPsec 控制面状态 (1=UP, 0=DOWN, -1=UNKNOWN) + 实时事件竖线', left: 10, top: 4, textStyle: { color: '#e2e8f0', fontSize: 12.5 } },
    tooltip: { trigger: 'axis', backgroundColor: '#0f172a', borderColor: '#334155', textStyle: { color: '#e2e8f0' } },
    grid: baseGrid,
    xAxis: { type: 'category', data: times, axisLabel, axisPointer: { show: true } },
    yAxis: { type: 'value', min: -1, max: 1, interval: 1, axisLabel, splitLine },
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
        name: 'CHILD SA',
        type: 'line',
        step: 'end',
        showSymbol: false,
        lineStyle: { width: 2, type: 'dashed' },
        itemStyle: { color: '#a855f7' },
        data: samples.map((s) => s.l2_child_state)
      }
    ]
  }, true)

  // Layer 3: Kernel XFRM Throughput & Error/Drop spikes
  charts[2].setOption({
    backgroundColor: 'transparent',
    title: { text: 'L3 · 内核 XFRM 吞吐 (Mbps) & XFRM/ACL 丢包增量', left: 10, top: 4, textStyle: { color: '#e2e8f0', fontSize: 12.5 } },
    tooltip: { trigger: 'axis', backgroundColor: '#0f172a', borderColor: '#334155', textStyle: { color: '#e2e8f0' } },
    grid: baseGrid,
    xAxis: { type: 'category', data: times, axisLabel, axisPointer: { show: true } },
    yAxis: [
      { type: 'value', name: 'Mbps', nameTextStyle: axisLabel, axisLabel, splitLine },
      { type: 'value', name: '错误/拦截', minInterval: 1, nameTextStyle: axisLabel, axisLabel, splitLine: { show: false } }
    ],
    series: [
      {
        name: 'RX (Mbps)',
        type: 'line',
        smooth: true,
        showSymbol: false,
        areaStyle: { opacity: 0.14 },
        itemStyle: { color: '#10b981' },
        data: samples.map((s) => Number((s.l3_rx_bps / 1_000_000).toFixed(2))),
        markLine: { silent: true, symbol: 'none', data: markLines }
      },
      {
        name: 'TX (Mbps)',
        type: 'line',
        smooth: true,
        showSymbol: false,
        areaStyle: { opacity: 0.12 },
        itemStyle: { color: '#60a5fa' },
        data: samples.map((s) => Number((s.l3_tx_bps / 1_000_000).toFixed(2)))
      },
      {
        name: 'XFRM Error + NFT Drop',
        type: 'bar',
        yAxisIndex: 1,
        itemStyle: { color: '#f59e0b' },
        data: samples.map((s) => s.l3_xfrm_err_delta + s.l3_nft_drop_delta)
      }
    ]
  }, true)

  // Layer 4: Cross-Tunnel End-to-End UDP Echo Probe
  charts[3].setOption({
    backgroundColor: 'transparent',
    title: { text: 'L4 · 跨隧道端到端业务 UDP 探测 (RTT/P95 ms & 丢包 %)', left: 10, top: 4, textStyle: { color: '#e2e8f0', fontSize: 12.5 } },
    tooltip: { trigger: 'axis', backgroundColor: '#0f172a', borderColor: '#334155', textStyle: { color: '#e2e8f0' } },
    grid: baseGrid,
    xAxis: { type: 'category', data: times, axisLabel, axisPointer: { show: true } },
    yAxis: [
      { type: 'value', name: 'RTT(ms)', nameTextStyle: axisLabel, axisLabel, splitLine },
      { type: 'value', name: '丢包%', min: 0, max: 100, nameTextStyle: axisLabel, axisLabel, splitLine: { show: false } }
    ],
    series: [
      {
        name: 'UDP RTT(ms)',
        type: 'line',
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#34d399' },
        data: samples.map((s) => Number(s.l4_udp_rtt_ms.toFixed(1))),
        markLine: { silent: true, symbol: 'none', data: markLines }
      },
      {
        name: 'UDP P95(ms)',
        type: 'line',
        smooth: true,
        showSymbol: false,
        lineStyle: { type: 'dotted' },
        itemStyle: { color: '#fbbf24' },
        data: samples.map((s) => Number(s.l4_udp_p95_ms.toFixed(1)))
      },
      {
        name: 'UDP 丢包%',
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

function stateBadge(v: number) {
  if (v === 1) return 'UP'
  if (v === 0) return 'DOWN'
  return 'UNKNOWN'
}
</script>

<template>
  <div>
    <div v-if="hovered" class="card" style="padding: 12px 16px; border-color: #3b82f6;">
      <div class="row">
        <strong>时间切面 {{ fmtTime(hovered.ts_ms) }}</strong>
        <span class="pill" :class="hovered.root_cause === 'VPN_HEALTHY_APP_SUSPECT' ? 'pill-ok' : hovered.root_cause === 'OBSERVATION_UNVERIFIED' ? 'pill-unknown' : 'pill-critical'">
          {{ hovered.root_cause }}
        </span>
        <span class="muted">L1外层: {{ stateBadge(hovered.l1_outer_state) }} ({{ hovered.l1_outer_rtt_ms.toFixed(1) }}ms / 丢包{{ (hovered.l1_outer_loss*100).toFixed(0) }}%)</span>
        <span class="muted">L2隧道: IKE={{ stateBadge(hovered.l2_ike_state) }} CHILD={{ stateBadge(hovered.l2_child_state) }}</span>
        <span class="muted">L3速率: RX {{ (hovered.l3_rx_bps/1e6).toFixed(2) }} / TX {{ (hovered.l3_tx_bps/1e6).toFixed(2) }} Mbps</span>
        <span class="muted">L4 UDP: {{ stateBadge(hovered.l4_udp_state) }} ({{ hovered.l4_udp_rtt_ms.toFixed(1) }}ms / 丢包{{ (hovered.l4_udp_loss*100).toFixed(0) }}%)</span>
      </div>
      <div style="margin-top: 6px; font-size: 13px; color: #f8fafc;">
        结论：{{ hovered.root_detail }}
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
