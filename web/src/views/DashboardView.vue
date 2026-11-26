<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { api, fmtDateTime, type DiagnosisResult, type MetricSample, type TimelineEvent } from '../api'
import { causeLabel, causeSummary, failoverModeLabel, sourceLabel, t } from '../i18n'

const emit = defineEmits<{ (e: 'navigate', tab: string, site?: string, focusTsMs?: number): void }>()

const overview = ref<any>(null)
const errMsg = ref('')
const okMsg = ref('')
const busySite = ref('')
const autoRefreshSec = ref(0)
let timer: number | null = null

async function load() {
  errMsg.value = ''
  try {
    overview.value = await api('/api/v1/overview')
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function seedDemo() {
  try {
    await api('/api/v1/diagnostics/seed-demo', { method: 'POST' })
    await load()
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function reconnectTunnel(siteId: string) {
  errMsg.value = ''
  okMsg.value = ''
  busySite.value = siteId
  try {
    await api(`/api/v1/tunnels/${encodeURIComponent(siteId)}/reconnect`, { method: 'POST' })
    okMsg.value = t('msgReconnectDone', { site: siteId })
    await load()
  } catch (e: any) {
    errMsg.value = e.message
  } finally {
    busySite.value = ''
  }
}

async function rekeyTunnel(siteId: string) {
  errMsg.value = ''
  okMsg.value = ''
  busySite.value = siteId
  try {
    await api(`/api/v1/tunnels/${encodeURIComponent(siteId)}/rekey`, {
      method: 'POST',
      body: JSON.stringify({ kind: 'child' })
    })
    okMsg.value = t('msgRekeyDone', { site: siteId })
    await load()
  } catch (e: any) {
    errMsg.value = e.message
  } finally {
    busySite.value = ''
  }
}

function resetTimer() {
  if (timer !== null) {
    window.clearInterval(timer)
    timer = null
  }
  if (autoRefreshSec.value > 0) {
    timer = window.setInterval(load, autoRefreshSec.value * 1000)
  }
}

watch(autoRefreshSec, resetTimer)

function pillClass(sev: string) {
  if (sev === 'ok') return 'pill-ok'
  if (sev === 'warning') return 'pill-warn'
  if (sev === 'critical') return 'pill-critical'
  return 'pill-unknown'
}

onMounted(() => {
  load()
  resetTimer()
})

onBeforeUnmount(() => {
  if (timer !== null) window.clearInterval(timer)
})
</script>

<template>
  <div>
    <div class="row" style="margin-bottom: 14px;">
      <div v-if="autoRefreshSec > 0" class="row" style="gap: 6px;">
        <span class="live-dot"></span>
        <span class="muted">{{ t('liveUpdating') }}</span>
      </div>
      <div class="spacer"></div>
      <select v-model.number="autoRefreshSec" class="select" style="width: 155px;">
        <option :value="0">{{ t('autoRefreshOff') }}</option>
        <option :value="15">{{ t('autoRefresh15s') }}</option>
        <option :value="30">{{ t('autoRefresh30s') }}</option>
        <option :value="60">{{ t('autoRefresh60s') }}</option>
      </select>
      <button v-if="overview?.demo_mode" class="btn btn-secondary" @click="seedDemo">{{ t('seedDemo') }}</button>
      <button class="btn" @click="load">{{ t('refresh') }}</button>
    </div>

    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>
    <div v-if="okMsg" class="alert-banner alert-ok">{{ okMsg }}</div>

    <template v-if="overview">
      <div
        class="alert-banner"
        :class="
          overview.overall.severity === 'ok'
            ? 'alert-ok'
            : overview.overall.severity === 'warning'
              ? 'alert-warn'
              : overview.overall.severity === 'critical'
                ? 'alert-critical'
                : 'alert-unknown'
        "
      >
        <div class="row">
          <span class="pill" :class="pillClass(overview.overall.severity)">{{ causeLabel(overview.overall.code) }}</span>
          <span>{{ causeSummary(overview.overall) }}</span>
        </div>
      </div>

      <div class="grid-4" style="margin-bottom: 16px;">
        <div class="card" style="margin-bottom: 0;">
          <div class="muted">{{ t('currentConfig') }}</div>
          <div style="font-size: 16px; font-weight: 700; margin-top: 6px;">
            {{ overview.active_profile?.id || t('notActivated') }}
          </div>
          <div class="muted" style="margin-top: 4px;">{{ t('savedConfigsCount', { n: overview.profile_count }) }}</div>
        </div>
        <div class="card" style="margin-bottom: 0;">
          <div class="muted">{{ t('failoverState') }}</div>
          <div style="font-size: 16px; font-weight: 700; margin-top: 6px;">
            {{ failoverModeLabel(overview.failover?.mode) }}
          </div>
          <div class="muted" style="margin-top: 4px;">
            {{ t('currentGateway') }}: {{ overview.failover?.hub_role === 'backup' ? t('gatewayBackup') : t('gatewayPrimary') }}
            · {{ t('activePath') }}: {{ overview.failover?.active_path === 'backup' ? t('pathBackup') : t('pathPrimary') }}
          </div>
        </div>
        <div class="card" style="margin-bottom: 0;">
          <div class="muted">{{ t('agentService') }}</div>
          <div style="margin-top: 8px;">
            <span class="pill" :class="overview.agent_online ? 'pill-ok' : 'pill-warn'">
              {{ overview.agent_online ? t('agentOnline') : t('agentOffline') }}
            </span>
          </div>
        </div>
        <div class="card" style="margin-bottom: 0;">
          <div class="muted">{{ t('monitoredTunnels') }}</div>
          <div style="font-size: 22px; font-weight: 700; margin-top: 4px;">{{ overview.sites?.length || 0 }}</div>
        </div>
      </div>

      <div class="card">
        <h3>{{ t('tunnelList') }}</h3>
        <div v-if="!overview.sites?.length" class="muted">
          {{ t('noTunnelData') }}
        </div>
        <table v-else class="table">
          <thead>
            <tr>
              <th>{{ t('colPeerSite') }}</th>
              <th>{{ t('colOuterLink') }}</th>
              <th>{{ t('colTunnelState') }}</th>
              <th>{{ t('colBandwidth') }}</th>
              <th>{{ t('colLanProbe') }}</th>
              <th>{{ t('colDiagnosis') }}</th>
              <th>{{ t('colAction') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in overview.sites as Array<{ sample: MetricSample; diagnosis: DiagnosisResult }>" :key="row.sample.site_id">
              <td>
                <strong>{{ row.sample.site_id }}</strong>
                <div class="muted">{{ row.sample.isp_label }}</div>
              </td>
              <td>
                <span class="pill" :class="row.sample.l1_outer_state === 1 ? 'pill-ok' : row.sample.l1_outer_state === 0 ? 'pill-critical' : 'pill-unknown'">
                  {{ row.sample.l1_outer_state === 1 ? `${row.sample.l1_outer_rtt_ms.toFixed(1)} ms` : row.sample.l1_outer_state === 0 ? t('stateDown') : t('stateDisabled') }}
                </span>
                <div class="muted">{{ t('lossPrefix') }} {{ (row.sample.l1_outer_loss * 100).toFixed(0) }}%</div>
              </td>
              <td>
                <span class="pill" :class="row.sample.l2_ike_state === 1 && row.sample.l2_child_state === 1 ? 'pill-ok' : 'pill-critical'">
                  {{ row.sample.l2_ike_state === 1 && row.sample.l2_child_state === 1 ? t('stateConnected') : t('stateDisconnected') }}
                </span>
              </td>
              <td>
                <div>{{ t('bwIn') }} {{ (row.sample.l3_rx_bps / 1e6).toFixed(2) }} / {{ t('bwOut') }} {{ (row.sample.l3_tx_bps / 1e6).toFixed(2) }} Mbps</div>
                <div class="muted">{{ t('errCountPrefix') }} +{{ row.sample.l3_xfrm_err_delta + row.sample.l3_nft_drop_delta }}</div>
              </td>
              <td>
                <span class="pill" :class="row.sample.l4_udp_state === 1 ? 'pill-ok' : row.sample.l4_udp_state === 0 ? 'pill-critical' : 'pill-unknown'">
                  {{ row.sample.l4_udp_state === 1 ? `${row.sample.l4_udp_rtt_ms.toFixed(1)} ms` : row.sample.l4_udp_state === 0 ? t('stateUnreachable') : t('stateUnchecked') }}
                </span>
              </td>
              <td>
                <span class="pill" :class="pillClass(row.diagnosis.severity)">{{ causeLabel(row.diagnosis.code) }}</span>
              </td>
              <td>
                <div class="row" style="gap: 6px;">
                  <button class="btn btn-secondary btn-sm" @click="emit('navigate', 'diagnostics', row.sample.site_id)">{{ t('viewMonitor') }}</button>
                  <button class="btn btn-secondary btn-sm" :disabled="busySite === row.sample.site_id" @click="reconnectTunnel(row.sample.site_id)">{{ t('btnReconnect') }}</button>
                  <button class="btn btn-secondary btn-sm" :disabled="busySite === row.sample.site_id" @click="rekeyTunnel(row.sample.site_id)">{{ t('btnRekey') }}</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <div class="row" style="margin-bottom: 10px;">
          <h3 style="margin: 0;">{{ t('recentEvents') }}</h3>
          <div class="spacer"></div>
          <button class="btn btn-secondary" @click="emit('navigate', 'events')">{{ t('viewAllEvents') }}</button>
        </div>
        <table v-if="overview.recent_events?.length" class="table">
          <thead>
            <tr>
              <th>{{ t('colTime') }}</th>
              <th>{{ t('colType') }}</th>
              <th>{{ t('colSite') }}</th>
              <th>{{ t('colSource') }}</th>
              <th>{{ t('colContent') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="ev in (overview.recent_events as TimelineEvent[]).slice().reverse().slice(0, 5)" :key="ev.id || ev.ts_ms">
              <td>{{ fmtDateTime(ev.ts_ms) }}</td>
              <td><code>{{ ev.category }}</code></td>
              <td>
                <a
                  v-if="ev.site_id"
                  href="#"
                  style="color: #60a5fa; text-decoration: none;"
                  @click.prevent="emit('navigate', 'diagnostics', ev.site_id, ev.ts_ms)"
                >
                  {{ ev.site_id }}
                </a>
                <span v-else>-</span>
              </td>
              <td>{{ sourceLabel(ev.source) }}</td>
              <td>{{ ev.title }}</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="muted">{{ t('noEvents') }}</div>
      </div>
    </template>
  </div>
</template>
