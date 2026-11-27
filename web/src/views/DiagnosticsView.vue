<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { api, fmtDateTime, type SyncedTimelineResponse } from '../api'
import { causeLabel, causeSummary, t } from '../i18n'
import SyncedFourLayerCharts from '../components/SyncedFourLayerCharts.vue'

const props = defineProps<{ initialSite?: string; focusTsMs?: number | null }>()
const emit = defineEmits<{ (e: 'navigate', tab: string, site?: string): void }>()

const site = ref(props.initialSite || 'ob-venue-1')
const siteOptions = ref<string[]>([])
const minutes = ref(60)
const activeFocusTs = ref<number | null>(props.focusTsMs ?? null)
const autoRefreshSec = ref(15)
const timeline = ref<SyncedTimelineResponse | null>(null)
const errMsg = ref('')

let timer: number | null = null

async function loadSites() {
  try {
    const ov = await api<any>('/api/v1/overview')
    const ids: string[] = (ov.sites || []).map((r: any) => r.sample.site_id)
    siteOptions.value = Array.from(new Set(ids))
    if (siteOptions.value.length && !siteOptions.value.includes(site.value)) {
      site.value = siteOptions.value[0]
    }
  } catch {
    // ignore
  }
}

async function load() {
  errMsg.value = ''
  try {
    const q = new URLSearchParams({ site: site.value })
    if (activeFocusTs.value && activeFocusTs.value > 0) {
      q.set('from', String(activeFocusTs.value - 30 * 60_000))
      q.set('to', String(activeFocusTs.value + 30 * 60_000))
    } else {
      q.set('minutes', String(minutes.value))
    }
    timeline.value = await api<SyncedTimelineResponse>(`/api/v1/diagnostics/timeline?${q}`)
  } catch (e: any) {
    errMsg.value = e.message
  }
}

function resetTimer() {
  if (timer !== null) {
    window.clearInterval(timer)
    timer = null
  }
  if (autoRefreshSec.value > 0 && !activeFocusTs.value) {
    timer = window.setInterval(load, autoRefreshSec.value * 1000)
  }
}

function exitFocusMode() {
  activeFocusTs.value = null
  load()
  resetTimer()
}

function onRangeChange() {
  activeFocusTs.value = null
  load()
  resetTimer()
}

watch(autoRefreshSec, resetTimer)

watch(
  () => [props.initialSite, props.focusTsMs] as const,
  ([newSite, newTs]) => {
    if (newSite) site.value = newSite
    activeFocusTs.value = newTs ?? null
    load()
    resetTimer()
  }
)

onMounted(async () => {
  await loadSites()
  await load()
  resetTimer()
})

onBeforeUnmount(() => {
  if (timer !== null) window.clearInterval(timer)
})
</script>

<template>
  <div>
    <div class="row" style="margin-bottom: 14px;">
      <select v-if="siteOptions.length" v-model="site" class="select" style="width: 190px;" @change="load">
        <option v-for="s in siteOptions" :key="s" :value="s">{{ s }}</option>
      </select>
      <input v-else v-model="site" class="input" style="width: 190px;" :placeholder="t('sitePlaceholder')" />

      <select v-model.number="minutes" class="select" style="width: 135px;" @change="onRangeChange">
        <option :value="15">{{ t('range15m') }}</option>
        <option :value="60">{{ t('range1h') }}</option>
        <option :value="360">{{ t('range6h') }}</option>
        <option :value="1440">{{ t('range24h') }}</option>
        <option :value="10080">{{ t('range7d') }}</option>
      </select>

      <select v-model.number="autoRefreshSec" class="select" style="width: 155px;" :disabled="Boolean(activeFocusTs)">
        <option :value="0">{{ t('autoRefreshOff') }}</option>
        <option :value="15">{{ t('autoRefresh15s') }}</option>
        <option :value="30">{{ t('autoRefresh30s') }}</option>
        <option :value="60">{{ t('autoRefresh60s') }}</option>
      </select>

      <button class="btn" @click="load">{{ t('refresh') }}</button>

      <div v-if="autoRefreshSec > 0 && !activeFocusTs" class="row" style="gap: 6px;">
        <span class="live-dot"></span>
        <span class="muted">{{ t('liveUpdating') }}</span>
      </div>
      <div class="spacer"></div>
      <span class="muted">{{ t('chartsSyncHint') }}</span>
    </div>

    <div v-if="activeFocusTs" class="alert-banner alert-warn">
      <div class="row">
        <span>{{ t('focusedEventWindow', { time: fmtDateTime(activeFocusTs) }) }}</span>
        <div class="spacer"></div>
        <button class="btn btn-secondary" @click="exitFocusMode">{{ t('backToLiveWindow') }}</button>
      </div>
    </div>

    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>

    <template v-if="timeline">
      <div
        class="alert-banner"
        :class="
          timeline.diagnosis.severity === 'ok'
            ? 'alert-ok'
            : timeline.diagnosis.severity === 'warning'
              ? 'alert-warn'
              : timeline.diagnosis.severity === 'critical'
                ? 'alert-critical'
                : 'alert-unknown'
        "
      >
        <div class="row">
          <span class="pill pill-info">{{ causeLabel(timeline.diagnosis.code) }}</span>
          <strong>{{ causeSummary(timeline.diagnosis) }}</strong>
        </div>
        <div v-if="timeline.diagnosis.evidence?.length" class="row" style="margin-top: 8px;">
          <span v-for="e in timeline.diagnosis.evidence" :key="e" class="pill pill-unknown">{{ e }}</span>
        </div>
      </div>

      <SyncedFourLayerCharts
        :samples="timeline.samples"
        :events="timeline.events"
        :focus-ts-ms="activeFocusTs"
      />

      <div class="card" style="padding: 12px 16px;">
        <div class="row">
          <span class="muted">{{ t('windowEventSummary', { n: timeline.events.length }) }}</span>
          <div class="spacer"></div>
          <button class="btn btn-secondary" @click="emit('navigate', 'events', site)">
            {{ t('openEventsPage') }}
          </button>
        </div>
      </div>
    </template>
  </div>
</template>
