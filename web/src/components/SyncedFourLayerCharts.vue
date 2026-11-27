<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'
import { fmtTime, type MetricSample, type TimelineEvent } from '../api'
import { causeLabel, lang, t } from '../i18n'
import { theme } from '../theme'

const props = defineProps<{
  samples: MetricSample[]
  events: TimelineEvent[]
  focusTsMs?: number | null
}>()

const c1 = ref<HTMLElement | null>(null)
const c2 = ref<HTMLElement | null>(null)
const c3 = ref<HTMLElement | null>(null)
const c4 = ref<HTMLElement | null>(null)
const hovered = ref<MetricSample | null>(null)

let charts: echarts.ECharts[] = []

function buildMarkLines(times: string[], samples: MetricSample[], events: TimelineEvent[], showLabels: boolean) {
  if (!samples.length || !events.length) return []
  const minGap = Math.max(2, Math.floor(samples.length * 0.12))
  const mapped = events.map((ev) => {
    let bestIdx = 0
    let bestDiff = Infinity
    for (let i = 0; i < samples.length; i++) {
      const diff = Math.abs(samples[i].ts_ms - ev.ts_ms)
      if (diff < bestDiff) {
        bestDiff = diff
        bestIdx = i
      }
    }
    return { ev, bestIdx }
  })
  mapped.sort((a, b) => a.bestIdx - b.bestIdx)

  const lines: any[] = []
  let lastLabeledIdx = -9999
  for (const { ev, bestIdx } of mapped) {
    const color =
      ev.severity === 'critical' ? '#ef4444' : ev.severity === 'warning' ? '#f59e0b' : '#2563eb'
    const canLabel = showLabels && bestIdx - lastLabeledIdx >= minGap
    if (canLabel) lastLabeledIdx = bestIdx
    lines.push({
      xAxis: times[bestIdx],
      lineStyle: { color, type: 'dashed', width: 1.3 },
      label: canLabel
        ? { show: true, formatter: ev.category, color, fontSize: 10, position: 'insideEndTop' }
        : { show: false }
    })
  }
  return lines
}

function renderCharts() {
  if (charts.length !== 4) return
  const isDark = theme.value === 'dark'
  const titleColor = isDark ? '#fafafa' : '#09090b'
  const axisColor = isDark ? '#a1a1aa' : '#71717a'
  const splitColor = isDark ? '#27272a' : '#f4f4f5'
  const axisLineColor = isDark ? '#27272a' : '#e4e4e7'
  const tipBg = isDark ? '#141418' : '#ffffff'
  const tipBorder = isDark ? '#27272a' : '#e4e4e7'
  const tipText = isDark ? '#fafafa' : '#09090b'

  const samples = props.samples || []
  const times = samples.map((s) => fmtTime(s.ts_ms))
  const markLinesLabeled = buildMarkLines(times, samples, props.events || [], true)
  const markLinesPlain = buildMarkLines(times, samples, props.events || [], false)
  if (samples.length) {
    if (props.focusTsMs && props.focusTsMs > 0) {
      let best = samples[0]
      let bestDiff = Math.abs(samples[0].ts_ms - props.focusTsMs)
      for (const s of samples) {
        const d = Math.abs(s.ts_ms - props.focusTsMs)
        if (d < bestDiff) {
          bestDiff = d
          best = s
        }
      }
      hovered.value = best
    } else {
      hovered.value = samples[samples.length - 1]
    }
  } else {
    hovered.value = null
  }

  const baseGrid = { left: 60, right: 54, top: 38, bottom: 26 }
  const axisLabel = { color: axisColor, fontSize: 11 }
  const splitLine = { lineStyle: { color: splitColor } }
  const axisLine = { lineStyle: { color: axisLineColor } }
  const tooltip = {
    trigger: 'axis',
    backgroundColor: tipBg,
    borderColor: tipBorder,
    borderWidth: 1,
    textStyle: { color: tipText, fontSize: 12 }
  }

  charts[0].setOption({
    backgroundColor: 'transparent',
    title: { text: t('chartL1Title'), left: 8, top: 4, textStyle: { color: titleColor, fontSize: 12.5, fontWeight: 600 } },
    tooltip,
    grid: baseGrid,
    xAxis: { type: 'category', data: times, axisLabel, axisLine, axisPointer: { show: true } },
    yAxis: [
      { type: 'value', name: 'RTT (ms)', nameTextStyle: axisLabel, axisLabel, splitLine },
      { type: 'value', name: t('axisLoss'), min: 0, max: 100, nameTextStyle: axisLabel, axisLabel, splitLine: { show: false } }
    ],
    series: [
      {
        name: t('seriesOuterRtt'),
        type: 'line',
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 1.8 },
        itemStyle: { color: isDark ? '#fafafa' : '#18181b' },
        data: samples.map((s) => Number(s.l1_outer_rtt_ms.toFixed(1))),
        markLine: { silent: true, symbol: 'none', data: markLinesLabeled }
      },
      {
        name: t('seriesOuterLoss'),
        type: 'bar',
        yAxisIndex: 1,
        itemStyle: { color: 'rgba(239, 68, 68, 0.5)' },
        data: samples.map((s) => Number((s.l1_outer_loss * 100).toFixed(1)))
      }
    ]
  }, true)

  charts[1].setOption({
    backgroundColor: 'transparent',
    title: { text: t('chartL2Title'), left: 8, top: 4, textStyle: { color: titleColor, fontSize: 12.5, fontWeight: 600 } },
    tooltip,
    grid: { ...baseGrid, left: 68 },
    xAxis: { type: 'category', data: times, axisLabel, axisLine, axisPointer: { show: true } },
    yAxis: {
      type: 'value',
      min: -1,
      max: 1,
      interval: 1,
      axisLabel: {
        color: axisColor,
        fontSize: 11,
        margin: 10,
        formatter: (v: number) => (v === 1 ? t('stOnline') : v === 0 ? t('stOffline') : t('stUnknown'))
      },
      splitLine
    },
    series: [
      {
        name: 'IKE SA',
        type: 'line',
        step: 'end',
        showSymbol: false,
        lineStyle: { width: 2 },
        itemStyle: { color: '#10b981' },
        data: samples.map((s) => s.l2_ike_state),
        markLine: { silent: true, symbol: 'none', data: markLinesPlain }
      },
      {
        name: 'IPsec SA',
        type: 'line',
        step: 'end',
        showSymbol: false,
        lineStyle: { width: 1.8, type: 'dashed' },
        itemStyle: { color: '#0284c7' },
        data: samples.map((s) => s.l2_child_state)
      }
    ]
  }, true)

  charts[2].setOption({
    backgroundColor: 'transparent',
    title: { text: t('chartL3Title'), left: 8, top: 4, textStyle: { color: titleColor, fontSize: 12.5, fontWeight: 600 } },
    tooltip,
    grid: baseGrid,
    xAxis: { type: 'category', data: times, axisLabel, axisLine, axisPointer: { show: true } },
    yAxis: [
      { type: 'value', name: t('axisBw'), nameTextStyle: axisLabel, axisLabel, splitLine },
      { type: 'value', name: t('axisErrs'), minInterval: 1, nameTextStyle: axisLabel, axisLabel, splitLine: { show: false } }
    ],
    series: [
      {
        name: t('seriesRxBw'),
        type: 'line',
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 1.8 },
        areaStyle: { opacity: isDark ? 0.14 : 0.08 },
        itemStyle: { color: '#10b981' },
        data: samples.map((s) => Number((s.l3_rx_bps / 1_000_000).toFixed(2))),
        markLine: { silent: true, symbol: 'none', data: markLinesPlain }
      },
      {
        name: t('seriesTxBw'),
        type: 'line',
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 1.8 },
        areaStyle: { opacity: isDark ? 0.1 : 0.06 },
        itemStyle: { color: isDark ? '#71717a' : '#3f3f46' },
        data: samples.map((s) => Number((s.l3_tx_bps / 1_000_000).toFixed(2)))
      },
      {
        name: t('seriesDropErr'),
        type: 'bar',
        yAxisIndex: 1,
        itemStyle: { color: '#f59e0b' },
        data: samples.map((s) => s.l3_xfrm_err_delta + s.l3_nft_drop_delta)
      }
    ]
  }, true)

  charts[3].setOption({
    backgroundColor: 'transparent',
    title: { text: t('chartL4Title'), left: 8, top: 4, textStyle: { color: titleColor, fontSize: 12.5, fontWeight: 600 } },
    tooltip,
    grid: baseGrid,
    xAxis: { type: 'category', data: times, axisLabel, axisLine, axisPointer: { show: true } },
    yAxis: [
      { type: 'value', name: 'RTT (ms)', nameTextStyle: axisLabel, axisLabel, splitLine },
      { type: 'value', name: t('axisLoss'), min: 0, max: 100, nameTextStyle: axisLabel, axisLabel, splitLine: { show: false } }
    ],
    series: [
      {
        name: t('seriesUdpRtt'),
        type: 'line',
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 1.8 },
        itemStyle: { color: '#10b981' },
        data: samples.map((s) => Number(s.l4_udp_rtt_ms.toFixed(1))),
        markLine: { silent: true, symbol: 'none', data: markLinesPlain }
      },
      {
        name: t('seriesUdpP95'),
        type: 'line',
        smooth: true,
        showSymbol: false,
        lineStyle: { type: 'dotted', width: 1.6 },
        itemStyle: { color: '#d97706' },
        data: samples.map((s) => Number(s.l4_udp_p95_ms.toFixed(1)))
      },
      {
        name: t('seriesUdpLoss'),
        type: 'bar',
        yAxisIndex: 1,
        itemStyle: { color: 'rgba(239, 68, 68, 0.55)' },
        data: samples.map((s) => Number((s.l4_udp_loss * 100).toFixed(1)))
      }
    ]
  }, true)

  if (samples.length > 0) {
    nextTick(() => handleResize())
  }
}

function handleResize() {
  for (const ch of charts) ch.resize()
}

onMounted(() => {
  const els = [c1.value, c2.value, c3.value, c4.value].filter(Boolean) as HTMLElement[]
  charts = els.map((el) => {
    const inst = echarts.init(el)
    inst.group = 'vpn-4layer-sync'
    inst.on('updateAxisPointer', (ev: any) => {
      const idx = ev?.axesInfo?.[0]?.value
      if (typeof idx === 'number' && props.samples[idx]) {
        hovered.value = props.samples[idx]
      }
    })
    return inst
  })
  echarts.connect('vpn-4layer-sync')
  renderCharts()
  window.addEventListener('resize', handleResize)
})

watch(() => [props.samples, props.events, props.focusTsMs, lang.value, theme.value], renderCharts, { deep: true })

onBeforeUnmount(() => {
  window.removeEventListener('resize', handleResize)
  for (const ch of charts) ch.dispose()
  charts = []
})
</script>

<template>
  <div>
    <div v-if="hovered" class="card" style="padding: 10px 16px; margin-bottom: 12px;">
      <div class="row" style="font-size: 12.5px;">
        <span class="code-chip">{{ fmtTime(hovered.ts_ms) }}</span>
        <span>{{ t('hoverOuter') }} <strong>{{ hovered.l1_outer_rtt_ms.toFixed(1) }} ms</strong> ({{ (hovered.l1_outer_loss * 100).toFixed(0) }}%)</span>
        <span>IKE <strong>{{ hovered.l2_ike_state === 1 ? t('stOnline') : hovered.l2_ike_state === 0 ? t('stOffline') : '-' }}</strong></span>
        <span>IPsec <strong>{{ hovered.l2_child_state === 1 ? t('stOnline') : hovered.l2_child_state === 0 ? t('stOffline') : '-' }}</strong></span>
        <span>{{ t('hoverBw') }} <strong>{{ (hovered.l3_rx_bps / 1e6).toFixed(2) }}/{{ (hovered.l3_tx_bps / 1e6).toFixed(2) }} Mbps</strong></span>
        <span>{{ t('hoverProbe') }} <strong>{{ hovered.l4_udp_state === 1 ? `${hovered.l4_udp_rtt_ms.toFixed(1)} ms` : hovered.l4_udp_state === 0 ? t('stOffline') : t('stUnknown') }}</strong></span>
        <div class="spacer"></div>
        <span class="pill" :class="hovered.root_cause === 'VPN_HEALTHY_APP_SUSPECT' ? 'pill-ok' : 'pill-warn'">
          {{ causeLabel(hovered.root_cause) }}
        </span>
      </div>
    </div>

    <div v-show="samples.length > 0">
      <div class="card" style="padding: 12px 10px;">
        <div ref="c1" style="width: 100%; height: 165px;"></div>
      </div>
      <div class="card" style="padding: 12px 10px;">
        <div ref="c2" style="width: 100%; height: 145px;"></div>
      </div>
      <div class="card" style="padding: 12px 10px;">
        <div ref="c3" style="width: 100%; height: 170px;"></div>
      </div>
      <div class="card" style="padding: 12px 10px;">
        <div ref="c4" style="width: 100%; height: 170px;"></div>
      </div>
    </div>
    <div v-if="!samples.length" class="card muted" style="padding: 32px 20px; text-align: center;">
      {{ t('noTelemetry') }}
    </div>
  </div>
</template>
