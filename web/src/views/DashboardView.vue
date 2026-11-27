<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { api, fmtDateTime, type DiagnosisResult, type MetricSample, type TimelineEvent } from '../api'
import { causeLabel, causeSummary, failoverModeLabel, sourceLabel, t } from '../i18n'

const emit = defineEmits<{ (e: 'navigate', tab: string, site?: string, focusTsMs?: number): void }>()

const overview = ref<any>(null)
const errMsg = ref('')
const okMsg = ref('')
const busySite = ref('')
const autoRefreshSec = ref(15)
const diagSiteId = ref('')
const diagLoading = ref(false)
const diagData = ref<any>(null)
const diagErr = ref('')
const copiedDiag = ref(false)
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

async function openDiagnostics(siteId: string) {
  diagSiteId.value = siteId
  await refreshDiagnostics()
}

async function refreshDiagnostics() {
  if (!diagSiteId.value) return
  diagLoading.value = true
  diagErr.value = ''
  try {
    diagData.value = await api(`/api/v1/tunnels/${encodeURIComponent(diagSiteId.value)}/diagnostics`)
  } catch (e: any) {
    diagErr.value = e.message
  } finally {
    diagLoading.value = false
  }
}

function closeDiagnostics() {
  diagSiteId.value = ''
  diagData.value = null
  diagErr.value = ''
}

async function copyDiagLogs() {
  if (!diagData.value) return
  const text = `=== swanctl --list-sas (${diagSiteId.value}) ===\n${diagData.value.swanctl_sas || ''}\n\n=== strongSwan logs ===\n${diagData.value.strongswan_logs || ''}`
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
    } else {
      throw new Error('fallback')
    }
  } catch {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    document.body.removeChild(ta)
  }
  copiedDiag.value = true
  setTimeout(() => {
    copiedDiag.value = false
  }, 1500)
}

function onKeyDown(ev: KeyboardEvent) {
  if (ev.key === 'Escape' && diagSiteId.value) closeDiagnostics()
}

onMounted(() => {
  load()
  resetTimer()
  window.addEventListener('keydown', onKeyDown)
})

onBeforeUnmount(() => {
  if (timer !== null) window.clearInterval(timer)
  window.removeEventListener('keydown', onKeyDown)
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
            <tr v-for="row in overview.sites as Array<{ sample: MetricSample; diagnosis: DiagnosisResult; meta?: any }>" :key="row.sample.site_id">
              <td>
                <strong>{{ row.sample.site_id }}</strong>
                <span v-if="row.meta?.display_name && row.meta.display_name !== row.sample.site_id" class="muted" style="margin-left: 6px;">{{ row.meta.display_name }}</span>
                <div class="muted" style="font-size: 11.5px;">
                  <code v-if="row.meta?.peer_public_ip">{{ row.meta.peer_public_ip }}</code>
                  <span v-if="row.meta?.lan_cidrs?.length"> · {{ row.meta.lan_cidrs.join(', ') }}</span>
                  <span v-else-if="row.sample.isp_label">{{ row.sample.isp_label }}</span>
                </div>
              </td>
              <td>
                <span class="pill" :class="row.sample.l1_outer_state === 1 ? 'pill-ok' : row.sample.l1_outer_state === 0 ? 'pill-critical' : 'pill-unknown'">
                  {{ row.sample.l1_outer_state === 1 ? `${row.sample.l1_outer_rtt_ms.toFixed(1)} ms` : row.sample.l1_outer_state === 0 ? t('stateDown') : t('statePending') }}
                </span>
                <div v-if="row.sample.l1_outer_state >= 0" class="muted">{{ t('lossPrefix') }} {{ (row.sample.l1_outer_loss * 100).toFixed(0) }}%</div>
              </td>
              <td>
                <template v-if="row.sample.l2_ike_state === -1 && row.sample.l2_child_state === -1">
                  <span class="pill pill-unknown">{{ t('statePending') }}</span>
                </template>
                <template v-else-if="row.sample.l2_ike_state === 1 && row.sample.l2_child_state === 1">
                  <span class="pill pill-ok">{{ t('stateConnected') }}</span>
                </template>
                <template v-else>
                  <div class="row" style="gap: 4px; flex-wrap: wrap;">
                    <span class="pill" :class="row.sample.l2_ike_state === 1 ? 'pill-ok' : 'pill-critical'">
                      IKE {{ row.sample.l2_ike_state === 1 ? '✓' : '✗' }}
                    </span>
                    <span class="pill" :class="row.sample.l2_child_state === 1 ? 'pill-ok' : 'pill-critical'">
                      IPsec {{ row.sample.l2_child_state === 1 ? '✓' : '✗' }}
                    </span>
                  </div>
                </template>
              </td>
              <td>
                <div>{{ t('bwIn') }} {{ (row.sample.l3_rx_bps / 1e6).toFixed(2) }} / {{ t('bwOut') }} {{ (row.sample.l3_tx_bps / 1e6).toFixed(2) }} Mbps</div>
                <div class="muted">{{ t('errCountPrefix') }} +{{ row.sample.l3_xfrm_err_delta + row.sample.l3_nft_drop_delta }}</div>
              </td>
              <td>
                <span class="pill" :class="row.sample.l4_udp_state === 1 ? 'pill-ok' : row.sample.l4_udp_state === 0 ? 'pill-critical' : 'pill-unknown'">
                  {{ row.sample.l4_udp_state === 1 ? `${row.sample.l4_udp_rtt_ms.toFixed(1)} ms` : row.sample.l4_udp_state === 0 ? t('stateUnreachable') : t('stateUnchecked') }}
                </span>
                <div v-if="row.meta?.probe_target" class="muted" style="font-size: 11px;"><code>{{ row.meta.probe_target }}</code></div>
              </td>
              <td>
                <span class="pill" :class="pillClass(row.diagnosis.severity)">{{ causeLabel(row.diagnosis.code) }}</span>
              </td>
              <td>
                <div class="row" style="gap: 6px;">
                  <button class="btn btn-secondary btn-sm" @click="openDiagnostics(row.sample.site_id)">{{ t('btnDiagLogs') }}</button>
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

    <!-- Slide-Over Drawer: Live Tunnel Diagnostics & strongSwan Logs -->
    <div v-if="diagSiteId" class="drawer-backdrop" @click.self="closeDiagnostics">
      <div class="drawer-panel" style="width: min(740px, 95vw);">
        <div class="drawer-header">
          <h3 style="margin: 0;">{{ t('diagDrawerTitle') }} · {{ diagSiteId }}</h3>
          <div class="row" style="gap: 6px;">
            <button class="btn btn-secondary btn-sm" :disabled="diagLoading" @click="refreshDiagnostics">{{ t('refreshLogsBtn') }}</button>
            <button class="btn btn-secondary btn-sm" :disabled="!diagData" @click="copyDiagLogs">
              {{ copiedDiag ? t('btnCopied') : t('copyLogsBtn') }}
            </button>
            <button class="btn btn-secondary btn-sm" :disabled="busySite === diagSiteId" @click="reconnectTunnel(diagSiteId).then(refreshDiagnostics)">
              {{ t('btnReconnect') }}
            </button>
            <button class="btn btn-secondary btn-sm" @click="closeDiagnostics">{{ t('btnClose') }}</button>
          </div>
        </div>
        <div class="drawer-body">
          <div v-if="diagErr" class="alert-banner alert-critical">{{ diagErr }}</div>
          <div v-if="diagLoading && !diagData" class="muted">{{ t('loading') }}</div>
          <template v-if="diagData">
            <div class="sub-card" style="padding: 12px; margin-bottom: 14px;">
              <div class="row" style="gap: 10px; flex-wrap: wrap;">
                <span>
                  <span class="muted">{{ t('ikePhase1') }}：</span>
                  <span class="pill" :class="diagData.ike_state === 1 ? 'pill-ok' : diagData.ike_state === 0 ? 'pill-critical' : 'pill-unknown'">
                    {{ diagData.ike_state === 1 ? t('stateConnected') : diagData.ike_state === 0 ? t('stateDisconnected') : t('statePending') }}
                  </span>
                </span>
                <span>
                  <span class="muted">{{ t('ipsecPhase2') }}：</span>
                  <span class="pill" :class="diagData.child_state === 1 ? 'pill-ok' : diagData.child_state === 0 ? 'pill-critical' : 'pill-unknown'">
                    {{ diagData.child_state === 1 ? t('stateConnected') : diagData.child_state === 0 ? t('stateDisconnected') : t('statePending') }}
                  </span>
                </span>
                <span v-if="diagData.peer_ip" class="muted">Peer: <code>{{ diagData.peer_ip }}</code></span>
                <span v-if="diagData.link_name" class="muted">XFRM: <code>{{ diagData.link_name }}</code></span>
                <div class="spacer"></div>
                <span v-if="diagData.captured_at_ms" class="muted" style="font-size: 11.5px;">{{ fmtDateTime(diagData.captured_at_ms) }}</span>
              </div>
            </div>

            <div class="field">
              <label>{{ t('saDetailsTitle') }}</label>
              <div class="code-block" style="max-height: 220px; font-size: 12px;">{{ diagData.swanctl_sas || '-' }}</div>
            </div>

            <div class="field" style="margin-bottom: 0;">
              <label>{{ t('strongswanLogTitle') }}</label>
              <div class="code-block" style="max-height: 320px; font-size: 11.5px;">{{ diagData.strongswan_logs || '-' }}</div>
            </div>
          </template>
        </div>
      </div>
    </div>
  </div>
</template>
