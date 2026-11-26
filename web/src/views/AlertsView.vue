<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, fmtDateTime } from '../api'

const rules = ref<any[]>([])
const history = ref<any[]>([])
const feishuURL = ref('')
const feishuSecret = ref('')
const msg = ref('')
const errMsg = ref('')

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
    msg.value = `规则 ${rule.name} 已更新`
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
    msg.value = '飞书测试告警发送成功！'
  } catch (e: any) {
    errMsg.value = e.message
  }
}

onMounted(load)
</script>

<template>
  <div>
    <h2 style="margin: 0 0 14px;">内置告警引擎 & 飞书通知（自带根因定界与来源标识）</h2>
    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>
    <div v-if="msg" class="alert-banner alert-ok">{{ msg }}</div>

    <div class="card">
      <h3>飞书机器人连通性测试（仅允许官方 open.feishu.cn Webhook）</h3>
      <div class="grid-2">
        <div class="field">
          <label>Feishu Webhook URL</label>
          <input v-model="feishuURL" class="input" placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..." />
        </div>
        <div class="field">
          <label>签名密钥（可选，不入数据库）</label>
          <input v-model="feishuSecret" type="password" class="input" placeholder="飞书机器人安全设置里的加签密钥" />
        </div>
      </div>
      <button class="btn" @click="testFeishu">发送飞书测试消息</button>
    </div>

    <div class="card">
      <h3>内置告警规则（去重冷却 · UNKNOWN 绝不误报 RECOVERED）</h3>
      <table class="table">
        <thead>
          <tr><th>启用</th><th>规则名</th><th>指标</th><th>阈值</th><th>冷却(秒)</th><th>级别</th><th>操作</th></tr>
        </thead>
        <tbody>
          <tr v-for="r in rules" :key="r.id">
            <td><input type="checkbox" v-model="r.enabled" /></td>
            <td><strong>{{ r.name }}</strong></td>
            <td><code>{{ r.metric }}</code></td>
            <td><input v-model.number="r.threshold" type="number" step="0.01" class="input" style="width: 90px;" /></td>
            <td><input v-model.number="r.cooldown_seconds" type="number" class="input" style="width: 85px;" /></td>
            <td><span class="pill" :class="r.severity === 'critical' ? 'pill-critical' : 'pill-warn'">{{ r.severity }}</span></td>
            <td><button class="btn btn-secondary" @click="saveRule(r)">保存</button></td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <h3>历史告警推送记录</h3>
      <table v-if="history.length" class="table">
        <thead>
          <tr><th>时间</th><th>状态</th><th>规则</th><th>来源</th><th>站点</th><th>根因码</th><th>送达</th></tr>
        </thead>
        <tbody>
          <tr v-for="h in history" :key="h.id">
            <td>{{ fmtDateTime(h.ts_ms) }}</td>
            <td><span class="pill" :class="h.status === 'FIRING' ? 'pill-critical' : h.status === 'RECOVERED' ? 'pill-ok' : 'pill-warn'">{{ h.status }}</span></td>
            <td>{{ h.alert_name }}</td>
            <td><code>{{ h.source }}</code></td>
            <td>{{ h.site_id }}</td>
            <td><code>{{ h.root_cause }}</code></td>
            <td>{{ h.delivered ? '✓' : h.error || '未配置发送器' }}</td>
          </tr>
        </tbody>
      </table>
      <div v-else class="muted">暂无告警推送记录。</div>
    </div>
  </div>
</template>
