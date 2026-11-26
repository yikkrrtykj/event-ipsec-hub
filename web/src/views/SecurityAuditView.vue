<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, downloadTextFile, fmtDateTime } from '../api'

const allowlistText = ref('')
const expiresDate = ref('')
const retentionDays = ref(14)
const auditLogs = ref<any[]>([])

const curPass = ref('')
const newPass = ref('')
const totpSecret = ref('')
const totpURI = ref('')
const totpCode = ref('')

const msg = ref('')
const errMsg = ref('')

async function load() {
  const [sec, aud] = await Promise.all([api('/api/v1/system/security'), api('/api/v1/audit')])
  allowlistText.value = (sec.allowlist || []).join('\n')
  retentionDays.value = sec.retention_days || 14
  if (sec.expires_at_ms > 0) {
    expiresDate.value = new Date(sec.expires_at_ms).toISOString().slice(0, 16)
  }
  auditLogs.value = aud.logs || []
}

async function saveSecurity() {
  errMsg.value = ''
  msg.value = ''
  try {
    const cidrs = allowlistText.value.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean)
    const expMs = expiresDate.value ? new Date(expiresDate.value).getTime() : 0
    await api('/api/v1/system/security', {
      method: 'PUT',
      body: JSON.stringify({ allowlist: cidrs, expires_at_ms: expMs, retention_days: retentionDays.value })
    })
    msg.value = 'Web 安全策略（IP 白名单 / 赛期自动到期 / 保留天数）已生效。'
    await load()
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function changePassword() {
  errMsg.value = ''
  msg.value = ''
  try {
    await api('/api/v1/auth/password', {
      method: 'POST',
      body: JSON.stringify({ current_password: curPass.value, new_password: newPass.value })
    })
    curPass.value = ''
    newPass.value = ''
    msg.value = '管理员密码已更新。'
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function setupTOTP() {
  const res = await api('/api/v1/auth/totp/setup', { method: 'POST' })
  totpSecret.value = res.secret
  totpURI.value = res.otpauth_uri
}

async function enableTOTP() {
  errMsg.value = ''
  try {
    await api('/api/v1/auth/totp/enable', { method: 'POST', body: JSON.stringify({ code: totpCode.value }) })
    msg.value = 'TOTP 手机动态码已启用！'
    totpCode.value = ''
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function downloadSignoff() {
  const res = await api('/api/v1/system/signoff')
  downloadTextFile(res.filename, res.content)
}

onMounted(load)
</script>

<template>
  <div>
    <div class="row" style="margin-bottom: 14px;">
      <h2 style="margin: 0;">安全护栏、审计日志 & 真机签收单 (#14)</h2>
      <div class="spacer"></div>
      <button class="btn btn-ok" @click="downloadSignoff">下载 #12/#14 生产上线签收单 (Markdown)</button>
    </div>

    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>
    <div v-if="msg" class="alert-banner alert-ok">{{ msg }}</div>

    <div class="grid-2">
      <div class="card">
        <h3>赛期直接 IP 访问护栏（白名单 + 到期自动停服）</h3>
        <div class="field">
          <label>允许打开 Web 控制台的来源 IP / CIDR（每行一个，留空则不限；127.0.0.1 始终放行）</label>
          <textarea v-model="allowlistText" class="textarea" rows="4" placeholder="203.0.113.5&#10;198.51.100.0/24"></textarea>
        </div>
        <div class="grid-2">
          <div class="field">
            <label>赛期截止时间（到期后自动拒绝公网访问）</label>
            <input v-model="expiresDate" type="datetime-local" class="input" />
          </div>
          <div class="field">
            <label>本地监控时序保留天数 (1~90 天)</label>
            <input v-model.number="retentionDays" type="number" min="1" max="90" class="input" />
          </div>
        </div>
        <button class="btn" @click="saveSecurity">保存安全护栏配置</button>
      </div>

      <div class="card">
        <h3>账号密码与 TOTP 手机 2FA</h3>
        <div class="grid-2">
          <div class="field">
            <label>当前密码</label>
            <input v-model="curPass" type="password" class="input" />
          </div>
          <div class="field">
            <label>新密码（至少 8 位）</label>
            <input v-model="newPass" type="password" class="input" />
          </div>
        </div>
        <div class="row" style="margin-bottom: 14px;">
          <button class="btn btn-secondary" @click="changePassword">修改密码</button>
          <button class="btn btn-secondary" @click="setupTOTP">生成 TOTP 绑定密钥</button>
        </div>
        <div v-if="totpSecret" class="alert-banner alert-unknown">
          <div>密钥（填入 Google/Microsoft Authenticator）：<code>{{ totpSecret }}</code></div>
          <div class="muted" style="word-break: break-all; margin: 4px 0;">{{ totpURI }}</div>
          <div class="row" style="margin-top: 8px;">
            <input v-model="totpCode" class="input" style="width: 140px;" placeholder="输入 6 位验证码" />
            <button class="btn btn-ok" @click="enableTOTP">验证并启用 2FA</button>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>操作审计日志（登录、变更、切备、明文 PSK 导出全量留痕）</h3>
      <table class="table">
        <thead>
          <tr><th>时间</th><th>操作人</th><th>来源 IP</th><th>动作</th><th>对象</th><th>结果</th><th>明细</th></tr>
        </thead>
        <tbody>
          <tr v-for="l in auditLogs" :key="l.id">
            <td>{{ fmtDateTime(l.ts_ms) }}</td>
            <td>{{ l.operator }}</td>
            <td><code>{{ l.remote_ip }}</code></td>
            <td><code>{{ l.action }}</code></td>
            <td>{{ l.target }}</td>
            <td><span class="pill" :class="l.status === 'PASS' ? 'pill-ok' : 'pill-critical'">{{ l.status }}</span></td>
            <td><code style="font-size: 11.5px;">{{ l.detail_json }}</code></td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
