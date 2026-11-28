<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { Copy, RefreshCw, RotateCw, Terminal, X } from 'lucide-vue-next'
import { api, fmtDateTime, type DiagnosisResult, type MetricSample, type TimelineEvent } from '../api'
import { causeLabel, causeSummary, failoverModeLabel, sourceLabel, t } from '../i18n'
import { copyToClipboard, toast } from '../toast'
import StatusDot from '../components/StatusDot.vue'

const emit = defineEmits<{ (e: 'navigate', tab: string, site?: string, focusTsMs?: number): void }>()

const overview = ref<any>(null)
const errMsg = ref('')
const busySite = ref('')
const autoRefreshSec = ref(15)
const diagSiteId = ref('')
const diagLoading = ref(false)
const diagData = ref<any>(null)
const diagErr = ref('')
const copiedDiag = ref(false)
let timer: number | null = null

const siteRows = computed(() => (overview.value?.sites || []) as Array<{ sample: MetricSample; diagnosis: DiagnosisResult; meta?: any }>)

const onlineCount = computed(() =>
  siteRows.value.filter((r) => r.sample.l2_ike_state === 1 && r.sample.l2_child_state === 1).length
)

const avgOuterRtt = computed(() => {
  const valid = siteRows.value.filter((r) => r.sample.l1_outer_state === 1 && r.sample.l1_outer_rtt_ms > 0)
  if (!valid.length) return '-'
  const avg = valid.reduce((acc, r) => acc + r.sample.l1_outer_rtt_ms, 0) / valid.length
  return `${avg.toFixed(1)} ms`
})

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
    toast.success(t('seedDemo'))
    await load()
  } catch (e: any) {
    toast.error(e.message)
  }
}

async function reconnectTunnel(siteId: string) {
  busySite.value = siteId
  try {
    await api(`/api/v1/tunnels/${encodeURIComponent(siteId)}/reconnect`, { method: 'POST' })
    toast.success(t('msgReconnectDone', { site: siteId }))
    await load()
  } catch (e: any) {
    toast.error(e.message)
  } finally {
    busySite.value = ''
  }
}

async function rekeyTunnel(siteId: string) {
  busySite.value = siteId
  try {
    await api(`/api/v1/tunnels/${encodeURIComponent(siteId)}/rekey`, {
      method: 'POST',
      body: JSON.stringify({ kind: 'child' })
    })
    toast.success(t('msgRekeyDone', { site: siteId }))
    await load()
  } catch (e: any) {
    toast.error(e.message)
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

function dotState(sev: string): 'ok' | 'warn' | 'critical' | 'unknown' {
  if (sev === 'ok') return 'ok'
  if (sev === 'warning') return 'warn'
  if (sev === 'critical') return 'critical'
  return 'unknown'
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

let diagBackdropDown = false

function closeDiagnostics() {
  diagBackdropDown = false
  diagSiteId.value = ''
  diagData.value = null
  diagErr.value = ''
}

function onDiagBackdropMouseDown() {
  diagBackdropDown = true
}

function onDiagBackdropClick() {
  if (diagBackdropDown) closeDiagnostics()
  diagBackdropDown = false
}

async function copyDiagLogs() {
  if (!diagData.value) return
  const text = `=== swanctl --list-sas (${diagSiteId.value}) ===\n${diagData.value.swanctl_sas || ''}\n\n=== strongSwan logs ===\n${diagData.value.strongswan_logs || ''}`
  if (await copyToClipboard(text)) {
    copiedDiag.value = true
    toast.success(t('btnCopied'))
    setTimeout(() => {
      copiedDiag.value = false
    }, 1500)
  }
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
    <div class="page-header">
      <div class="row">
        <h2 class="page-title">{{ t('navDashboard') }}</h2>
        <StatusDot v-if="autoRefreshSec > 0" state="ok" :label="t('liveUpdating')" :pulse="true" />
      </div>
      <div class="row" style="gap: 8px;">
        <select v-model.number="autoRefreshSec" class="select" style="width: 145px;">
          <option :value="0">{{ t('autoRefreshOff') }}</option>
          <option :value="15">{{ t('autoRefresh15s') }}</option>
          <option :value="30">{{ t('autoRefresh30s') }}</option>
          <option :value="60">{{ t('autoRefresh60s') }}</option>
        </select>
        <button v-if="overview?.demo_mode" class="btn btn-secondary" @click="seedDemo">{{ t('seedDemo') }}</button>
        <button class="btn btn-secondary" @click="load">
          <RefreshCw :size="14" />
          <span>{{ t('refresh') }}</span>
        </button>
      </div>
    </div>

    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>

    <template v-if="overview">
      <!-- Joined 4-Cell Minimalist KPI Strip -->
      <div class="kpi-strip">
        <div class="kpi-cell">
          <div class="kpi-label">{{ t('onlineTunnelsLabel') }}</div>
          <div class="row" style="gap: 8px;">
            <span class="kpi-value">{{ onlineCount }} / {{ siteRows.length }}</span>
            <StatusDot :state="siteRows.length > 0 && onlineCount === siteRows.length ? 'ok' : siteRows.length === 0 ? 'unknown' : 'warn'" />
          </div>
          <div class="kpi-sub">{{ overview.active_profile?.id || t('notActivated') }}</div>
        </div>
        <div class="kpi-cell">
          <div class="kpi-label">{{ t('avgOuterRttLabel') }}</div>
          <div class="kpi-value">{{ avgOuterRtt }}</div>
          <div class="kpi-sub">{{ t('savedConfigsCount', { n: overview.profile_count }) }}</div>
        </div>
        <div class="kpi-cell">
          <div class="kpi-label">{{ t('failoverState') }}</div>
          <div class="kpi-value" style="font-size: 17px;">{{ failoverModeLabel(overview.failover?.mode) }}</div>
          <div class="kpi-sub">
            {{ overview.failover?.hub_role === 'backup' ? t('gatewayBackup') : t('gatewayPrimary') }}
            · {{ overview.failover?.active_path === 'backup' ? t('pathBackup') : t('pathPrimary') }}
          </div>
        </div>
        <div class="kpi-cell">
          <div class="kpi-label">{{ t('agentService') }}</div>
          <div style="padding-top: 4px;">
            <StatusDot
              :state="overview.agent_online ? 'ok' : 'warn'"
              :label="overview.agent_online ? t('agentOnline') : t('agentOffline')"
              :pulse="overview.agent_online"
            />
          </div>
          <div class="kpi-sub">{{ causeLabel(overview.overall.code) }}</div>
        </div>
      </div>

      <!-- Overall Diagnosis Notice (shown prominently only for active warning/critical faults) -->
      <div
        v-if="(overview.overall.severity === 'warning' || overview.overall.severity === 'critical') && siteRows.length > 0"
        class="alert-banner"
        :class="overview.overall.severity === 'warning' ? 'alert-warn' : 'alert-critical'"
      >
        <div class="row">
          <StatusDot :state="dotState(overview.overall.severity)" :label="causeLabel(overview.overall.code)" />
          <span>{{ causeSummary(overview.overall) }}</span>
        </div>
      </div>

      <!-- VPN Tunnels Table -->
      <div class="card card-flush">
        <div class="card-header">
          <h3>{{ t('tunnelList') }}</h3>
          <button class="btn btn-secondary btn-sm" @click="emit('navigate', 'config')">{{ t('navConfig') }}</button>
        </div>
        <div v-if="!siteRows.length" class="muted" style="padding: 24px 20px;">
          {{ t('noTunnelData') }}
        </div>
        <table v-else class="table">
          <thead>
            <tr>
              <th>{{ t('colPeerSite') }}</th>
              <th>{{ t('peerPublicIp') }} / {{ t('colLanCidrs') }}</th>
              <th>{{ t('colOuterLink') }}</th>
              <th>{{ t('colTunnelState') }}</th>
              <th>{{ t('colBandwidth') }}</th>
              <th>{{ t('colLanProbe') }}</th>
              <th>{{ t('colAction') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in siteRows" :key="row.sample.site_id">
              <td>
                <div style="font-weight: 600;">{{ row.sample.site_id }}</div>
                <div v-if="row.meta?.display_name && row.meta.display_name !== row.sample.site_id" class="muted" style="font-size: 12px;">
                  {{ row.meta.display_name }}
                </div>
              </td>
              <td>
                <div class="row" style="gap: 6px;">
                  <span v-if="row.meta?.peer_public_ip" class="code-chip">{{ row.meta.peer_public_ip }}</span>
                  <span v-for="cidr in (row.meta?.lan_cidrs || [])" :key="cidr" class="code-chip">{{ cidr }}</span>
                </div>
              </td>
              <td>
                <StatusDot
                  :state="row.sample.l1_outer_state === 1 ? 'ok' : row.sample.l1_outer_state === 0 ? 'critical' : 'unknown'"
                  :label="row.sample.l1_outer_state === 1 ? `${row.sample.l1_outer_rtt_ms.toFixed(1)} ms` : row.sample.l1_outer_state === 0 ? t('stateDown') : t('statePending')"
                />
                <div v-if="row.sample.l1_outer_state >= 0" class="muted" style="font-size: 11.5px;">
                  {{ t('lossPrefix') }} {{ (row.sample.l1_outer_loss * 100).toFixed(0) }}%
                </div>
              </td>
              <td>
                <template v-if="row.sample.l2_ike_state === -1 && row.sample.l2_child_state === -1">
                  <StatusDot state="unknown" :label="t('statePending')" />
                </template>
                <template v-else-if="row.sample.l2_ike_state === 1 && row.sample.l2_child_state === 1">
                  <StatusDot state="ok" :label="t('stateConnected')" />
                </template>
                <template v-else-if="row.sample.l2_ike_state === 0 && row.sample.l2_child_state === 0">
                  <StatusDot state="critical" :label="t('stateDisconnected')" />
                </template>
                <template v-else>
                  <div style="display: flex; flex-direction: column; gap: 3px;">
                    <StatusDot :state="row.sample.l2_ike_state === 1 ? 'ok' : 'critical'" :label="`IKE ${row.sample.l2_ike_state === 1 ? t('stateConnected') : t('stateDisconnected')}`" />
                    <StatusDot :state="row.sample.l2_child_state === 1 ? 'ok' : 'critical'" :label="`IPsec ${row.sample.l2_child_state === 1 ? t('stateConnected') : t('stateDisconnected')}`" />
                  </div>
                </template>
              </td>
              <td>
                <div style="font-size: 12.5px;">
                  {{ (row.sample.l3_rx_bps / 1e6).toFixed(2) }} / {{ (row.sample.l3_tx_bps / 1e6).toFixed(2) }} Mbps
                </div>
                <div v-if="row.sample.l3_xfrm_err_delta + row.sample.l3_nft_drop_delta > 0" class="muted" style="font-size: 11.5px; color: var(--warn-fg);">
                  {{ t('errCountPrefix') }} +{{ row.sample.l3_xfrm_err_delta + row.sample.l3_nft_drop_delta }}
                </div>
              </td>
              <td>
                <StatusDot
                  :state="row.sample.l4_udp_state === 1 ? 'ok' : row.sample.l4_udp_state === 0 ? 'critical' : 'unknown'"
                  :label="row.sample.l4_udp_state === 1 ? `${row.sample.l4_udp_rtt_ms.toFixed(1)} ms` : row.sample.l4_udp_state === 0 ? t('stateUnreachable') : t('stateUnchecked')"
                />
                <div v-if="row.meta?.probe_target" class="muted" style="font-size: 11px;"><code>{{ row.meta.probe_target }}</code></div>
              </td>
              <td>
                <div class="row" style="gap: 2px;">
                  <button class="btn btn-ghost" @click="openDiagnostics(row.sample.site_id)">{{ t('btnDiagLogs') }}</button>
                  <button class="btn btn-ghost" @click="emit('navigate', 'diagnostics', row.sample.site_id)">{{ t('viewMonitor') }}</button>
                  <button class="btn btn-ghost" :disabled="busySite === row.sample.site_id" @click="reconnectTunnel(row.sample.site_id)">{{ t('btnReconnect') }}</button>
                  <button class="btn btn-ghost" :disabled="busySite === row.sample.site_id" @click="rekeyTunnel(row.sample.site_id)">{{ t('btnRekey') }}</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Recent Events -->
      <div class="card card-flush">
        <div class="card-header">
          <h3>{{ t('recentEvents') }}</h3>
          <button class="btn btn-secondary btn-sm" @click="emit('navigate', 'events')">{{ t('viewAllEvents') }}</button>
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
              <td class="muted">{{ fmtDateTime(ev.ts_ms) }}</td>
              <td><span class="code-chip">{{ ev.category }}</span></td>
              <td>
                <button
                  v-if="ev.site_id"
                  class="btn btn-ghost"
                  style="padding: 2px 6px;"
                  @click="emit('navigate', 'diagnostics', ev.site_id, ev.ts_ms)"
                >
                  {{ ev.site_id }}
                </button>
                <span v-else class="muted">-</span>
              </td>
              <td class="muted">{{ sourceLabel(ev.source) }}</td>
              <td>{{ ev.title }}</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="muted" style="padding: 20px;">{{ t('noEvents') }}</div>
      </div>
    </template>

    <!-- Slide-Over Drawer: Live Tunnel Diagnostics & strongSwan Logs -->
    <div v-if="diagSiteId" class="drawer-backdrop" @mousedown.self="onDiagBackdropMouseDown" @click.self="onDiagBackdropClick">
      <div class="drawer-panel" style="width: min(740px, 95vw);" @mousedown="diagBackdropDown = false">
        <div class="drawer-header">
          <div class="row" style="gap: 8px;">
            <Terminal :size="16" />
            <h3>{{ t('diagDrawerTitle') }} · {{ diagSiteId }}</h3>
          </div>
          <div class="row" style="gap: 6px;">
            <button class="btn btn-secondary btn-sm" :disabled="diagLoading" @click="refreshDiagnostics">
              <RefreshCw :size="13" />
              <span>{{ t('refreshLogsBtn') }}</span>
            </button>
            <button class="btn btn-secondary btn-sm" :disabled="!diagData" @click="copyDiagLogs">
              <Copy :size="13" />
              <span>{{ copiedDiag ? t('btnCopied') : t('copyLogsBtn') }}</span>
            </button>
            <button class="btn btn-secondary btn-sm" :disabled="busySite === diagSiteId" @click="reconnectTunnel(diagSiteId).then(refreshDiagnostics)">
              <RotateCw :size="13" />
              <span>{{ t('btnReconnect') }}</span>
            </button>
            <button class="btn btn-secondary btn-icon" @click="closeDiagnostics">
              <X :size="15" />
            </button>
          </div>
        </div>
        <div class="drawer-body">
          <div v-if="diagErr" class="alert-banner alert-critical">{{ diagErr }}</div>
          <div v-if="diagLoading && !diagData" class="muted">{{ t('loading') }}</div>
          <template v-if="diagData">
            <div class="sub-card">
              <div class="row" style="gap: 14px;">
                <span>
                  <span class="muted">{{ t('ikePhase1') }}：</span>
                  <StatusDot
                    :state="diagData.ike_state === 1 ? 'ok' : diagData.ike_state === 0 ? 'critical' : 'unknown'"
                    :label="diagData.ike_state === 1 ? t('stateConnected') : diagData.ike_state === 0 ? t('stateDisconnected') : t('statePending')"
                  />
                </span>
                <span>
                  <span class="muted">{{ t('ipsecPhase2') }}：</span>
                  <StatusDot
                    :state="diagData.child_state === 1 ? 'ok' : diagData.child_state === 0 ? 'critical' : 'unknown'"
                    :label="diagData.child_state === 1 ? t('stateConnected') : diagData.child_state === 0 ? t('stateDisconnected') : t('statePending')"
                  />
                </span>
                <span v-if="diagData.peer_ip" class="code-chip">{{ diagData.peer_ip }}</span>
                <span v-if="diagData.link_name" class="code-chip">{{ diagData.link_name }}</span>
                <div class="spacer"></div>
                <span v-if="diagData.captured_at_ms" class="muted" style="font-size: 11.5px;">{{ fmtDateTime(diagData.captured_at_ms) }}</span>
              </div>
            </div>

            <div class="field">
              <label>{{ t('saDetailsTitle') }}</label>
              <div class="code-block" style="max-height: 220px;">{{ diagData.swanctl_sas || '-' }}</div>
            </div>

            <div class="field" style="margin-bottom: 0;">
              <label>{{ t('strongswanLogTitle') }}</label>
              <div class="code-block" style="max-height: 340px;">{{ diagData.strongswan_logs || '-' }}</div>
            </div>
          </template>
        </div>
      </div>
    </div>
  </div>
</template>
