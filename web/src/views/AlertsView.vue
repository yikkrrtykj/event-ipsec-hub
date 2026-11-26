<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, fmtDateTime } from '../api'

const rules = ref<any[]>([])
const history = ref<any[]>([])
const feishuURL = ref('')
const feishuSecret = ref('')
const msg = ref('')
const errMsg = ref('')

function statusLabel(st: string): string {
  if (st === 'FIRING') return '告警中'
  if (st === 'RECOVERED') return '已恢复'
  if (st === 'DATA_UNAVAILABLE') return '数据不可用'
  return st
}

function sourceLabel(src: string): string {
  if (src === 'self_hosted_hub') return '自建网关'
  if (src === 'cloud_backup_vpn') return '云端备线'
  return src || '-'
}

async function load() {
  const [r1, r2] = await Promise.all([api('/api/v1/alerts/rules'), api('/api/v1/alerts/history')])
  rules.value = r1.rules || []
  history.value = r2.history || []
}

async function saveRule(rule: any) {
  errMsg.value = ''
  msg.value = ''
  try {
    await api('/api/v1/alerts/rules', { method: 'PUT', body: JSON.stringify(rule) })
    msg.value = `策略 ${rule.name} 已保存。`
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function testFeishu() {
  errMsg.value = ''
  msg.value = ''
  try {
    await api('/api/v1/alerts/feishu/test', {
      method: 'POST',
      body: JSON.stringify({ webhook_url: feishuURL.value, secret: feishuSecret.value })
    })
    msg.value = '飞书测试消息已发送。'
  } catch (e: any) {
    errMsg.value = e.message
  }
}

onMounted(load)
</script>

<template>
  <div>
    <h2 style="margin: 0 0 14px; font-size: 18px;">告警管理</h2>
    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>
    <div v-if="msg" class="alert-banner alert-ok">{{ msg }}</div>

    <div class="card">
      <h3>飞书通知</h3>
      <div class="grid-2">
        <div class="field">
          <label>Webhook 地址（仅支持 open.feishu.cn）</label>
          <input v-model="feishuURL" class="input" placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..." />
        </div>
        <div class="field">
          <label>签名密钥（可选）</label>
          <input v-model="feishuSecret" type="password" class="input" placeholder="机器人安全设置中的加签密钥" />
        </div>
      </div>
      <button class="btn" @click="testFeishu">发送测试消息</button>
    </div>

    <div class="card">
      <h3>告警策略</h3>
      <table class="table">
        <thead>
          <tr><th>启用</th><th>策略名称</th><th>监控指标</th><th>阈值</th><th>冷却(秒)</th><th>级别</th><th>操作</th></tr>
        </thead>
        <tbody>
          <tr v-for="r in rules" :key="r.id">
            <td><input type="checkbox" v-model="r.enabled" /></td>
            <td><strong>{{ r.name }}</strong></td>
            <td><code>{{ r.metric }}</code></td>
            <td><input v-model.number="r.threshold" type="number" step="0.01" class="input" style="width: 90px;" /></td>
            <td><input v-model.number="r.cooldown_seconds" type="number" class="input" style="width: 85px;" /></td>
            <td>
              <span class="pill" :class="r.severity === 'critical' ? 'pill-critical' : 'pill-warn'">
                {{ r.severity === 'critical' ? '严重' : '警告' }}
              </span>
            </td>
            <td><button class="btn btn-secondary" @click="saveRule(r)">保存</button></td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <h3>告警记录</h3>
      <table v-if="history.length" class="table">
        <thead>
          <tr><th>时间</th><th>状态</th><th>策略</th><th>来源</th><th>站点</th><th>诊断码</th><th>通知状态</th></tr>
        </thead>
        <tbody>
          <tr v-for="h in history" :key="h.id">
            <td>{{ fmtDateTime(h.ts_ms) }}</td>
            <td>
              <span class="pill" :class="h.status === 'FIRING' ? 'pill-critical' : h.status === 'RECOVERED' ? 'pill-ok' : 'pill-warn'">
                {{ statusLabel(h.status) }}
              </span>
            </td>
            <td>{{ h.alert_name }}</td>
            <td>{{ sourceLabel(h.source) }}</td>
            <td>{{ h.site_id }}</td>
            <td><code>{{ h.root_cause }}</code></td>
            <td>{{ h.delivered ? '已送达' : h.error || '未配置通道' }}</td>
          </tr>
        </tbody>
      </table>
      <div v-else class="muted">暂无告警记录。</div>
    </div>
  </div>
</template>
