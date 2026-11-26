<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, fmtDateTime } from '../api'
import { failoverModeLabel, t } from '../i18n'

const state = ref<any>(null)
const reason = ref('manual_switch')
const applyGate = ref(true)
const force = ref(false)
const msg = ref('')
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
  msg.value = ''
  try {
    const res = await api('/api/v1/failover/switch-backup', {
      method: 'POST',
      body: JSON.stringify({ reason: reason.value, apply_gate: applyGate.value })
    })
    state.value = res.state
    msg.value = t('msgSwitchedBackup')
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function failback() {
  errMsg.value = ''
  msg.value = ''
  try {
    const res = await api('/api/v1/failover/failback', {
      method: 'POST',
      body: JSON.stringify({ force: force.value, apply_gate: applyGate.value })
    })
    state.value = res.state
    msg.value = t('msgFailbackDone')
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function setRole(role: string) {
  errMsg.value = ''
  msg.value = ''
  try {
    const res = await api('/api/v1/failover/set-role', {
      method: 'POST',
      body: JSON.stringify({ role })
    })
    state.value = res.state
    msg.value = role === 'backup' ? t('msgRoleBackup') : t('msgRolePrimary')
  } catch (e: any) {
    errMsg.value = e.message
  }
}

onMounted(load)
</script>

<template>
  <div>
    <h2 style="margin: 0 0 14px; font-size: 18px;">{{ t('navFailover') }}</h2>
    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>
    <div v-if="msg" class="alert-banner alert-ok">{{ msg }}</div>

    <div v-if="state" class="grid-3">
      <div class="card">
        <div class="muted">{{ t('switchState') }}</div>
        <div style="font-size: 20px; font-weight: 600; margin: 8px 0;">{{ failoverModeLabel(state.mode) }}</div>
        <div class="muted">{{ t('backupLockHint') }}</div>
      </div>
      <div class="card">
        <div class="muted">{{ t('currentRoutePath') }}</div>
        <div style="font-size: 20px; font-weight: 600; margin: 8px 0;">
          {{ state.active_path === 'backup' ? t('pathBackup') : t('pathPrimary') }}
        </div>
        <div class="muted">{{ t('consecFail', { n: state.consecutive_primary_failures }) }}</div>
      </div>
      <div class="card">
        <div class="muted">{{ t('localGatewayRole') }}</div>
        <div style="font-size: 20px; font-weight: 600; margin: 8px 0;">
          {{ state.hub_role === 'backup' ? t('gatewayBackup') : t('gatewayPrimary') }}
        </div>
        <div class="row">
          <button class="btn btn-secondary" @click="setRole('primary')">{{ t('setPrimaryBtn') }}</button>
          <button class="btn btn-secondary" @click="setRole('backup')">{{ t('setBackupBtn') }}</button>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>{{ t('switchOps') }}</h3>
      <div class="row" style="margin-bottom: 12px;">
        <input v-model="reason" class="input" style="width: 240px;" :placeholder="t('switchNotePh')" />
        <label style="display: flex; align-items: center; gap: 6px;">
          <input type="checkbox" v-model="applyGate" />
          {{ t('gateCheckbox') }}
        </label>
      </div>
      <div class="row">
        <button class="btn btn-danger" @click="switchBackup">{{ t('btnSwitchBackup') }}</button>
        <div class="spacer"></div>
        <label style="display: flex; align-items: center; gap: 6px;">
          <input type="checkbox" v-model="force" />
          {{ t('forceFailbackCb') }}
        </label>
        <button class="btn btn-ok" @click="failback">{{ t('btnFailback') }}</button>
      </div>
    </div>

    <div v-if="state?.history?.length" class="card">
      <h3>{{ t('switchHistory') }}</h3>
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
            <td>{{ fmtDateTime(Math.round((h.at || 0) * 1000)) }}</td>
            <td><code>{{ h.event }}</code></td>
            <td><code>{{ JSON.stringify(h) }}</code></td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
