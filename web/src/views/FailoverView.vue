<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, fmtDateTime } from '../api'

const state = ref<any>(null)
const reason = ref('manual_drill')
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
    msg.value = res.detail || res.action
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
    msg.value = res.detail || res.action
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
    msg.value = res.detail
  } catch (e: any) {
    errMsg.value = e.message
  }
}

onMounted(load)
</script>

<template>
  <div>
    <h2 style="margin: 0 0 14px;">主备门控锁 & 主备角色互换台 (#12 / #13)</h2>
    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>
    <div v-if="msg" class="alert-banner alert-ok">{{ msg }}</div>

    <div v-if="state" class="grid-3">
      <div class="card">
        <div class="muted">当前门控模式</div>
        <div style="font-size: 20px; font-weight: 700; margin: 8px 0;">{{ state.mode }}</div>
        <div class="muted">进入 BACKUP_LOCKED 后永不自动抢占回切，必须等主线稳定满 180 秒并由人工确认。</div>
      </div>
      <div class="card">
        <div class="muted">当前活动业务路径</div>
        <div style="font-size: 20px; font-weight: 700; margin: 8px 0;">{{ state.active_path }}</div>
        <div class="muted">连续失败次数：{{ state.consecutive_primary_failures }}</div>
      </div>
      <div class="card">
        <div class="muted">本自建 Hub 主备角色 (#12)</div>
        <div style="font-size: 20px; font-weight: 700; margin: 8px 0;">
          {{ state.hub_role === 'backup' ? '自建备 Hub ↔ 云为主' : '自建主 Hub ↔ 云为备' }}
        </div>
        <div class="row">
          <button class="btn btn-secondary" @click="setRole('primary')">设为自建主</button>
          <button class="btn btn-secondary" @click="setRole('backup')">设为自建备</button>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>受控切换与人工回切操作</h3>
      <div class="row" style="margin-bottom: 12px;">
        <input v-model="reason" class="input" style="width: 240px;" placeholder="切换原因（记入审计）" />
        <label style="display: flex; align-items: center; gap: 6px;">
          <input type="checkbox" v-model="applyGate" />
          联动 Hub XFRM 门控（切备时置 DOWN 防山石自动抢占，回切时置 UP 并恢复内层路由）
        </label>
      </div>
      <div class="row">
        <button class="btn btn-danger" @click="switchBackup">手动切备并锁死 (BACKUP_LOCKED)</button>
        <div class="spacer"></div>
        <label style="display: flex; align-items: center; gap: 6px;">
          <input type="checkbox" v-model="force" />
          紧急强制回切 (--force，跳过 180s 保持窗口)
        </label>
        <button class="btn btn-ok" @click="failback">人工确认回切至主路</button>
      </div>
    </div>

    <div v-if="state?.history?.length" class="card">
      <h3>切换历史记录</h3>
      <table class="table">
        <thead>
          <tr><th>时间</th><th>事件</th><th>详情</th></tr>
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
