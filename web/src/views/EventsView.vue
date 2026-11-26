<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { api, downloadTextFile, fmtDateTime, type TimelineEvent } from '../api'
import { sourceLabel, t } from '../i18n'

const props = defineProps<{ initialSite?: string }>()
const emit = defineEmits<{ (e: 'navigate', tab: string, site?: string): void }>()

const events = ref<TimelineEvent[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(25)
const loading = ref(false)
const errMsg = ref('')

const siteOptions = ref<string[]>([])
const site = ref(props.initialSite || '')
const severity = ref('')
const layer = ref('')
const keyword = ref('')
const startTime = ref('')
const endTime = ref('')
const activePreset = ref<'1h' | '6h' | '24h' | '7d' | 'all' | 'custom'>('24h')

const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value)))

function toLocalInput(ms: number): string {
  const d = new Date(ms)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function applyPreset(preset: '1h' | '6h' | '24h' | '7d' | 'all') {
  activePreset.value = preset
  if (preset === 'all') {
    startTime.value = ''
    endTime.value = ''
  } else {
    const now = Date.now()
    const minsMap = { '1h': 60, '6h': 360, '24h': 1440, '7d': 10080 }
    startTime.value = toLocalInput(now - minsMap[preset] * 60_000)
    endTime.value = toLocalInput(now + 60_000)
  }
  search(1)
}

function onCustomTimeChange() {
  activePreset.value = 'custom'
}

async function loadSites() {
  try {
    const ov = await api<any>('/api/v1/overview')
    const ids: string[] = (ov.sites || []).map((r: any) => r.sample.site_id)
    siteOptions.value = Array.from(new Set(ids))
  } catch {
    // ignore
  }
}

async function search(targetPage = page.value) {
  page.value = Math.max(1, targetPage)
  loading.value = true
  errMsg.value = ''
  try {
    const params = new URLSearchParams({
      limit: String(pageSize.value),
      offset: String((page.value - 1) * pageSize.value)
    })
    if (site.value) params.set('site', site.value)
    if (severity.value) params.set('severity', severity.value)
    if (layer.value) params.set('layer', layer.value)
    if (keyword.value.trim()) params.set('q', keyword.value.trim())
    if (startTime.value) {
      const fromMs = new Date(startTime.value).getTime()
      if (!Number.isNaN(fromMs) && fromMs > 0) params.set('from', String(fromMs))
    }
    if (endTime.value) {
      const toMs = new Date(endTime.value).getTime()
      if (!Number.isNaN(toMs) && toMs > 0) params.set('to', String(toMs))
    }
    const res = await api<{ events: TimelineEvent[]; total: number }>(`/api/v1/events?${params}`)
    events.value = res.events || []
    total.value = res.total || 0
  } catch (e: any) {
    errMsg.value = e.message
  } finally {
    loading.value = false
  }
}

function resetFilters() {
  site.value = ''
  severity.value = ''
  layer.value = ''
  keyword.value = ''
  applyPreset('24h')
}

function layerText(l: string): string {
  const m: Record<string, string> = {
    L1_OUTER: t('layerL1'),
    L2_IPSEC: t('layerL2'),
    L3_XFRM: t('layerL3'),
    L4_UDP: t('layerL4'),
    FAILOVER: t('layerFailover'),
    OPS: t('layerOps')
  }
  return m[l] || l || '-'
}

function exportCSV() {
  const esc = (v: any) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const header = ['Time', 'Severity', 'Layer', 'Site', 'Category', 'Source', 'RootCause', 'Message']
  const rows = events.value.map((ev) => [
    fmtDateTime(ev.ts_ms),
    ev.severity,
    ev.layer,
    ev.site_id,
    ev.category,
    ev.source,
    ev.root_cause,
    ev.title
  ])
  const csv = '\uFEFF' + [header, ...rows].map((r) => r.map(esc).join(',')).join('\n')
  downloadTextFile(`vpn-events-page${page.value}.csv`, csv)
}

watch(() => props.initialSite, (v) => {
  if (v !== undefined) {
    site.value = v
    search(1)
  }
})

onMounted(async () => {
  await loadSites()
  applyPreset('24h')
})
</script>

<template>
  <div>
    <div class="row" style="margin-bottom: 14px;">
      <h2 style="margin: 0; font-size: 18px;">{{ t('navEvents') }}</h2>
      <div class="spacer"></div>
      <button class="btn btn-secondary" :disabled="!events.length" @click="exportCSV">{{ t('btnExportCsv') }}</button>
    </div>

    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>

    <!-- Search & Time Range Filter Card -->
    <div class="card">
      <div class="row" style="margin-bottom: 12px;">
        <button class="btn" :class="activePreset === '1h' ? '' : 'btn-secondary'" @click="applyPreset('1h')">{{ t('range1h') }}</button>
        <button class="btn" :class="activePreset === '6h' ? '' : 'btn-secondary'" @click="applyPreset('6h')">{{ t('range6h') }}</button>
        <button class="btn" :class="activePreset === '24h' ? '' : 'btn-secondary'" @click="applyPreset('24h')">{{ t('range24h') }}</button>
        <button class="btn" :class="activePreset === '7d' ? '' : 'btn-secondary'" @click="applyPreset('7d')">{{ t('range7d') }}</button>
        <button class="btn" :class="activePreset === 'all' ? '' : 'btn-secondary'" @click="applyPreset('all')">{{ t('allTime') }}</button>
        <div class="spacer"></div>
        <div class="row">
          <label class="muted">{{ t('startTime') }}</label>
          <input v-model="startTime" type="datetime-local" class="input" style="width: 195px;" @change="onCustomTimeChange" />
          <label class="muted">{{ t('endTime') }}</label>
          <input v-model="endTime" type="datetime-local" class="input" style="width: 195px;" @change="onCustomTimeChange" />
        </div>
      </div>

      <div class="row">
        <select v-model="site" class="select" style="width: 165px;" @change="search(1)">
          <option value="">{{ t('allSites') }}</option>
          <option v-for="s in siteOptions" :key="s" :value="s">{{ s }}</option>
        </select>

        <select v-model="severity" class="select" style="width: 130px;" @change="search(1)">
          <option value="">{{ t('allLevels') }}</option>
          <option value="critical">{{ t('sevCritical') }}</option>
          <option value="warning">{{ t('sevWarning') }}</option>
          <option value="info">{{ t('sevInfo') }}</option>
        </select>

        <select v-model="layer" class="select" style="width: 155px;" @change="search(1)">
          <option value="">{{ t('allLayers') }}</option>
          <option value="L1_OUTER">{{ t('layerL1') }}</option>
          <option value="L2_IPSEC">{{ t('layerL2') }}</option>
          <option value="L3_XFRM">{{ t('layerL3') }}</option>
          <option value="L4_UDP">{{ t('layerL4') }}</option>
          <option value="FAILOVER">{{ t('layerFailover') }}</option>
          <option value="OPS">{{ t('layerOps') }}</option>
        </select>

        <input
          v-model="keyword"
          class="input"
          style="flex: 1; min-width: 200px;"
          :placeholder="t('keywordPh')"
          @keyup.enter="search(1)"
        />
        <button class="btn" :disabled="loading" @click="search(1)">{{ t('btnSearch') }}</button>
        <button class="btn btn-secondary" @click="resetFilters">{{ t('btnReset') }}</button>
      </div>
    </div>

    <!-- Paginated Event Results -->
    <div class="card">
      <table v-if="events.length" class="table">
        <thead>
          <tr>
            <th style="width: 165px;">{{ t('colTime') }}</th>
            <th style="width: 80px;">{{ t('colLevel') }}</th>
            <th style="width: 120px;">{{ t('colLayer') }}</th>
            <th style="width: 130px;">{{ t('colSite') }}</th>
            <th style="width: 160px;">{{ t('colEvent') }}</th>
            <th style="width: 110px;">{{ t('colSource') }}</th>
            <th>{{ t('colDetail') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="ev in events" :key="ev.id || ev.ts_ms">
            <td>{{ fmtDateTime(ev.ts_ms) }}</td>
            <td>
              <span class="pill" :class="ev.severity === 'critical' ? 'pill-critical' : ev.severity === 'warning' ? 'pill-warn' : 'pill-info'">
                {{ ev.severity === 'critical' ? t('sevCritical') : ev.severity === 'warning' ? t('sevWarning') : t('sevInfo') }}
              </span>
            </td>
            <td class="muted">{{ layerText(ev.layer) }}</td>
            <td>
              <a
                v-if="ev.site_id"
                href="#"
                style="color: #60a5fa; text-decoration: none; font-weight: 500;"
                @click.prevent="emit('navigate', 'diagnostics', ev.site_id)"
              >
                {{ ev.site_id }}
              </a>
              <span v-else class="muted">-</span>
            </td>
            <td><code>{{ ev.category }}</code></td>
            <td>{{ sourceLabel(ev.source) }}</td>
            <td>{{ ev.title }}</td>
          </tr>
        </tbody>
      </table>
      <div v-else class="muted">{{ t('noMatchedEvents') }}</div>

      <div class="row" style="margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--border);">
        <span class="muted">{{ t('pageSummary', { total, page, pages: totalPages }) }}</span>
        <div class="spacer"></div>
        <select v-model.number="pageSize" class="select" style="width: 115px;" @change="search(1)">
          <option :value="25">{{ t('perPage', { n: 25 }) }}</option>
          <option :value="50">{{ t('perPage', { n: 50 }) }}</option>
          <option :value="100">{{ t('perPage', { n: 100 }) }}</option>
        </select>
        <button class="btn btn-secondary" :disabled="page <= 1" @click="search(page - 1)">{{ t('prevPage') }}</button>
        <button class="btn btn-secondary" :disabled="page >= totalPages" @click="search(page + 1)">{{ t('nextPage') }}</button>
      </div>
    </div>
  </div>
</template>
