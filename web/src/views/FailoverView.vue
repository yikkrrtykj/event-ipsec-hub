<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, fmtDateTime } from '../api'
import { failoverModeLabel, t } from '../i18n'
import { toast } from '../toast'
import StatusDot from '../components/StatusDot.vue'

const state = ref<any>(null)
const reason = ref('manual_switch')
const applyGate = ref(true)
const force = ref(false)
const errMsg = ref('')

async function load() {
  errMsg.value = ''
  try {
    const res = await api('/api/v1/failover')
    state.value = res.state
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function switchBackup() {
  errMsg.value = ''
  try {
    const res = await api('/api/v1/failover/switch-backup', {
      method: 'POST',
      body: JSON.stringify({ reason: reason.value, apply_gate: applyGate.value })
    })
    state.value = res.state
    toast.success(t('msgSwitchedBackup'))
  } catch (e: any) {
    errMsg.value = e.message
    toast.error(e.message)
  }
}

async function failback() {
  errMsg.value = ''
  try {
    const res = await api('/api/v1/failover/failback', {
      method: 'POST',
      body: JSON.stringify({ force: force.value, apply_gate: applyGate.value })
    })
    state.value = res.state
    toast.success(t('msgFailbackDone'))
  } catch (e: any) {
    errMsg.value = e.message
    toast.error(e.message)
  }
}

async function setRole(role: string) {
  errMsg.value = ''
  try {
    const res = await api('/api/v1/failover/set-role', {
      method: 'POST',
      body: JSON.stringify({ role })
    })
    state.value = res.state
    toast.success(role === 'backup' ? t('msgRoleBackup') : t('msgRolePrimary'))
  } catch (e: any) {
    errMsg.value = e.message
    toast.error(e.message)
  }
}

function summarizeHistory(h: any): string {
  const parts: string[] = []
  if (h.from || h.to) parts.push(`${failoverModeLabel(h.from)} → ${failoverModeLabel(h.to)}`)
  if (h.role) parts.push(h.role === 'backup' ? t('gatewayBackup') : t('gatewayPrimary'))
  if (h.reason) parts.push(h.reason)
  if (h.gate_applied) parts.push('XFRM Gate')
  return parts.join(' · ') || '-'
}

onMounted(load)
</script>

<template>
  <div>
    <div class="page-header">
      <h2 class="page-title">{{ t('navFailover') }}</h2>
    </div>
    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>

    <div v-if="state" class="kpi-strip" style="grid-template-columns: repeat(3, minmax(0, 1fr));">
      <div class="kpi-cell">
        <div class="kpi-label">{{ t('switchState') }}</div>
        <div style="margin-top: 2px;">
          <StatusDot
            :state="state.mode === 'PRIMARY_ACTIVE' ? 'ok' : state.mode === 'BACKUP_LOCKED' ? 'warn' : 'unknown'"
            :label="failoverModeLabel(state.mode)"
          />
        </div>
        <div class="kpi-sub">{{ t('backupLockHint') }}</div>
      </div>
      <div class="kpi-cell">
        <div class="kpi-label">{{ t('currentRoutePath') }}</div>
        <div class="kpi-value" style="font-size: 18px;">
          {{ state.active_path === 'backup' ? t('pathBackup') : t('pathPrimary') }}
        </div>
        <div class="kpi-sub">{{ t('consecFail', { n: state.consecutive_primary_failures }) }}</div>
      </div>
      <div class="kpi-cell">
        <div class="kpi-label">{{ t('localGatewayRole') }}</div>
        <div class="kpi-value" style="font-size: 18px;">
          {{ state.hub_role === 'backup' ? t('gatewayBackup') : t('gatewayPrimary') }}
        </div>
        <div class="row" style="margin-top: 6px; gap: 6px;">
          <button class="btn btn-secondary btn-sm" @click="setRole('primary')">{{ t('setPrimaryBtn') }}</button>
          <button class="btn btn-secondary btn-sm" @click="setRole('backup')">{{ t('setBackupBtn') }}</button>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>{{ t('switchOps') }}</h3>
      <div class="row" style="margin-bottom: 14px;">
        <input v-model="reason" class="input" style="width: 240px;" :placeholder="t('switchNotePh')" />
        <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
          <input type="checkbox" v-model="applyGate" />
          <span>{{ t('gateCheckbox') }}</span>
        </label>
      </div>
      <div class="row">
        <button class="btn btn-danger-solid" @click="switchBackup">{{ t('btnSwitchBackup') }}</button>
        <div class="spacer"></div>
        <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
          <input type="checkbox" v-model="force" />
          <span>{{ t('forceFailbackCb') }}</span>
        </label>
        <button class="btn btn-ok" @click="failback">{{ t('btnFailback') }}</button>
      </div>
    </div>

    <div v-if="state?.history?.length" class="card card-flush">
      <div class="card-header">
        <h3>{{ t('switchHistory') }}</h3>
      </div>
      <table class="table">
        <thead>
          <tr>
            <th>{{ t('colTime') }}</th>
            <th>{{ t('colEvent') }}</th>
            <th>{{ t('colDetails') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(h, i) in state.history.slice().reverse()" :key="i">
            <td class="muted">{{ fmtDateTime(Math.round((h.at || 0) * 1000)) }}</td>
            <td><span class="code-chip">{{ h.event }}</span></td>
            <td>{{ summarizeHistory(h) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
