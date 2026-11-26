<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { api, fmtDateTime, type SyncedTimelineResponse } from '../api'
import { causeLabel, causeSummary, t } from '../i18n'
import SyncedFourLayerCharts from '../components/SyncedFourLayerCharts.vue'

const props = defineProps<{ initialSite?: string }>()

const site = ref(props.initialSite || 'ob-venue-1')
const siteOptions = ref<string[]>([])
const minutes = ref(60)
const timeline = ref<SyncedTimelineResponse | null>(null)
const errMsg = ref('')

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
    const q = new URLSearchParams({ site: site.value, minutes: String(minutes.value) })
    timeline.value = await api<SyncedTimelineResponse>(`/api/v1/diagnostics/timeline?${q}`)
  } catch (e: any) {
    errMsg.value = e.message
  }
}

watch(() => props.initialSite, (v) => {
  if (v) {
    site.value = v
    load()
  }
})

onMounted(async () => {
  await loadSites()
  await load()
})
</script>

<template>
  <div>
    <div class="row" style="margin-bottom: 14px;">
      <select v-if="siteOptions.length" v-model="site" class="select" style="width: 190px;" @change="load">
        <option v-for="s in siteOptions" :key="s" :value="s">{{ s }}</option>
      </select>
      <input v-else v-model="site" class="input" style="width: 190px;" :placeholder="t('sitePlaceholder')" />

      <select v-model.number="minutes" class="select" style="width: 135px;" @change="load">
        <option :value="15">{{ t('range15m') }}</option>
        <option :value="60">{{ t('range1h') }}</option>
        <option :value="360">{{ t('range6h') }}</option>
        <option :value="1440">{{ t('range24h') }}</option>
        <option :value="10080">{{ t('range7d') }}</option>
      </select>
      <button class="btn" @click="load">{{ t('refresh') }}</button>
      <div class="spacer"></div>
      <span class="muted">{{ t('chartsSyncHint') }}</span>
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

      <SyncedFourLayerCharts :samples="timeline.samples" :events="timeline.events" />

      <div class="card">
        <h3>{{ t('eventLog') }}</h3>
        <table v-if="timeline.events.length" class="table">
          <thead>
            <tr>
              <th>{{ t('colTime') }}</th>
              <th>{{ t('colEvent') }}</th>
              <th>{{ t('colLevel') }}</th>
              <th>{{ t('colDetail') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="ev in timeline.events" :key="ev.id || ev.ts_ms">
              <td>{{ fmtDateTime(ev.ts_ms) }}</td>
              <td><code>{{ ev.category }}</code></td>
              <td>
                <span class="pill" :class="ev.severity === 'critical' ? 'pill-critical' : ev.severity === 'warning' ? 'pill-warn' : 'pill-info'">
                  {{ ev.severity === 'critical' ? t('sevCritical') : ev.severity === 'warning' ? t('sevWarning') : t('sevInfo') }}
                </span>
              </td>
              <td>{{ ev.title }}</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="muted">{{ t('noWindowEvents') }}</div>
      </div>
    </template>
  </div>
</template>
