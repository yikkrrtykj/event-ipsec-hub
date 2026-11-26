<script setup lang="ts">
import { onMounted, ref } from 'vue'
import QRCode from 'qrcode'
import { api, downloadTextFile, fmtDateTime } from '../api'
import { t } from '../i18n'

const allowlistText = ref('')
const expiresDate = ref('')
const retentionDays = ref(14)
const auditLogs = ref<any[]>([])

const curPass = ref('')
const newPass = ref('')
const totpSecret = ref('')
const totpURI = ref('')
const totpQR = ref('')
const totpCode = ref('')
const copiedSecret = ref(false)

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
    msg.value = t('msgSecuritySaved')
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
    msg.value = t('msgPassUpdated')
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function setupTOTP() {
  errMsg.value = ''
  const res = await api('/api/v1/auth/totp/setup', { method: 'POST' })
  totpSecret.value = res.secret
  totpURI.value = res.otpauth_uri
  totpQR.value = await QRCode.toDataURL(res.otpauth_uri, {
    width: 184,
    margin: 2,
    color: { dark: '#0f172a', light: '#ffffff' }
  })
}

async function copyTotpSecret() {
  if (!totpSecret.value) return
  try {
    await navigator.clipboard.writeText(totpSecret.value)
    copiedSecret.value = true
    setTimeout(() => {
      copiedSecret.value = false
    }, 1500)
  } catch {
    // ignore clipboard restrictions
  }
}

async function enableTOTP() {
  errMsg.value = ''
  try {
    await api('/api/v1/auth/totp/enable', { method: 'POST', body: JSON.stringify({ code: totpCode.value }) })
    msg.value = t('msgTotpEnabled')
    totpCode.value = ''
    totpSecret.value = ''
    totpURI.value = ''
    totpQR.value = ''
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
      <h2 style="margin: 0; font-size: 18px;">{{ t('navSecurity') }}</h2>
      <div class="spacer"></div>
      <button class="btn btn-secondary" @click="downloadSignoff">{{ t('exportSignoff') }}</button>
    </div>

    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>
    <div v-if="msg" class="alert-banner alert-ok">{{ msg }}</div>

    <div class="grid-2">
      <div class="card">
        <h3>{{ t('accessControl') }}</h3>
        <div class="field">
          <label>{{ t('allowlistLabel') }}</label>
          <textarea v-model="allowlistText" class="textarea" rows="4" placeholder="203.0.113.5&#10;198.51.100.0/24"></textarea>
        </div>
        <div class="grid-2">
          <div class="field">
            <label>{{ t('expireTimeLabel') }}</label>
            <input v-model="expiresDate" type="datetime-local" class="input" />
          </div>
          <div class="field">
            <label>{{ t('retentionLabel') }}</label>
            <input v-model.number="retentionDays" type="number" min="1" max="90" class="input" />
          </div>
        </div>
        <button class="btn" @click="saveSecurity">{{ t('btnSaveSettings') }}</button>
      </div>

      <div class="card">
        <h3>{{ t('accountSecurity') }}</h3>
        <div class="grid-2">
          <div class="field">
            <label>{{ t('currentPass') }}</label>
            <input v-model="curPass" type="password" class="input" />
          </div>
          <div class="field">
            <label>{{ t('newPass') }}</label>
            <input v-model="newPass" type="password" class="input" />
          </div>
        </div>
        <div class="row" style="margin-bottom: 14px;">
          <button class="btn btn-secondary" @click="changePassword">{{ t('btnChangePass') }}</button>
          <button class="btn btn-secondary" @click="setupTOTP">{{ t('btnSetupTotp') }}</button>
        </div>
        <div v-if="totpSecret" class="sub-card" style="padding: 14px; margin-top: 4px;">
          <div style="display: flex; gap: 16px; align-items: flex-start; flex-wrap: wrap;">
            <div v-if="totpQR" style="background: #ffffff; padding: 8px; border-radius: 8px; flex-shrink: 0;">
              <img :src="totpQR" alt="TOTP QR Code" style="display: block; width: 168px; height: 168px;" />
            </div>
            <div style="flex: 1; min-width: 220px;">
              <div style="font-weight: 600; margin-bottom: 6px;">{{ t('totpScanHint') }}</div>
              <div class="muted" style="margin-bottom: 6px;">{{ t('totpManualFallback') }}</div>
              <div class="row" style="margin-bottom: 10px;">
                <code style="font-size: 13px; letter-spacing: 0.5px;">{{ totpSecret }}</code>
                <button class="btn btn-secondary btn-sm" @click="copyTotpSecret">
                  {{ copiedSecret ? t('btnCopied') : t('btnCopySecret') }}
                </button>
              </div>
              <div class="row">
                <input v-model="totpCode" class="input" style="width: 150px;" :placeholder="t('totpCodePh')" @keyup.enter="enableTOTP" />
                <button class="btn btn-ok" @click="enableTOTP">{{ t('btnEnableTotp') }}</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>{{ t('auditLogTitle') }}</h3>
      <table class="table">
        <thead>
          <tr>
            <th>{{ t('colTime') }}</th>
            <th>{{ t('colOperator') }}</th>
            <th>{{ t('colSourceIp') }}</th>
            <th>{{ t('colAction') }}</th>
            <th>{{ t('colTarget') }}</th>
            <th>{{ t('colResult') }}</th>
            <th>{{ t('colDetails') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="l in auditLogs" :key="l.id">
            <td>{{ fmtDateTime(l.ts_ms) }}</td>
            <td>{{ l.operator }}</td>
            <td><code>{{ l.remote_ip }}</code></td>
            <td><code>{{ l.action }}</code></td>
            <td>{{ l.target }}</td>
            <td><span class="pill" :class="l.status === 'PASS' ? 'pill-ok' : 'pill-critical'">{{ l.status === 'PASS' ? t('resPass') : t('resFail') }}</span></td>
            <td><code style="font-size: 11.5px;">{{ l.detail_json }}</code></td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
