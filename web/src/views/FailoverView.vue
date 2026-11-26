<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, fmtDateTime } from '../api'

const state = ref<any>(null)
const reason = ref('manual_switch')
const applyGate = ref(true)
const force = ref(false)
const msg = ref('')
const errMsg = ref('')

function modeLabel(mode: string): string {
  if (mode === 'PRIMARY_ACTIVE') return '主路运行'
  if (mode === 'BACKUP_LOCKED') return '备路锁定'
  if (mode === 'FAILBACK_READY') return '待人工回切'
  return mode || '-'
}

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
    msg.value = '已切换至备路并锁定。'
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
    msg.value = '已回切至主路。'
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
    msg.value = role === 'backup' ? '本端角色已设为备网关。' : '本端角色已设为主网关。'
  } catch (e: any) {
    errMsg.value = e.message
  }
}

onMounted(load)
</script>

<template>
  <div>
    <h2 style="margin: 0 0 14px; font-size: 18px;">主备切换</h2>
    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>
    <div v-if="msg" class="alert-banner alert-ok">{{ msg }}</div>

    <div v-if="state" class="grid-3">
      <div class="card">
        <div class="muted">切换状态</div>
        <div style="font-size: 20px; font-weight: 600; margin: 8px 0;">{{ modeLabel(state.mode) }}</div>
        <div class="muted">锁定备路后不会自动回切，需主路稳定 180 秒并人工确认。</div>
      </div>
      <div class="card">
        <div class="muted">当前路由路径</div>
        <div style="font-size: 20px; font-weight: 600; margin: 8px 0;">
          {{ state.active_path === 'backup' ? '备路' : '主路' }}
        </div>
        <div class="muted">连续探测失败：{{ state.consecutive_primary_failures }} 次</div>
      </div>
      <div class="card">
        <div class="muted">本端网关角色</div>
        <div style="font-size: 20px; font-weight: 600; margin: 8px 0;">
          {{ state.hub_role === 'backup' ? '备网关' : '主网关' }}
        </div>
        <div class="row">
          <button class="btn btn-secondary" @click="setRole('primary')">设为主网关</button>
          <button class="btn btn-secondary" @click="setRole('backup')">设为备网关</button>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>切换操作</h3>
      <div class="row" style="margin-bottom: 12px;">
        <input v-model="reason" class="input" style="width: 240px;" placeholder="切换备注" />
        <label style="display: flex; align-items: center; gap: 6px;">
          <input type="checkbox" v-model="applyGate" />
          同步关闭本端 XFRM 通道（防止对端路由自动回切）
        </label>
      </div>
      <div class="row">
        <button class="btn btn-danger" @click="switchBackup">切换至备路</button>
        <div class="spacer"></div>
        <label style="display: flex; align-items: center; gap: 6px;">
          <input type="checkbox" v-model="force" />
          强制回切（跳过 180 秒观察期）
        </label>
        <button class="btn btn-ok" @click="failback">确认回切主路</button>
      </div>
    </div>

    <div v-if="state?.history?.length" class="card">
      <h3>切换记录</h3>
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
