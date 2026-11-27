<script setup lang="ts">
import { onMounted, ref } from 'vue'
import QRCode from 'qrcode'
import { Copy, Download, ExternalLink, KeyRound, Plus, ShieldCheck } from 'lucide-vue-next'
import { api, downloadTextFile, fmtDateTime } from '../api'
import { t } from '../i18n'
import { copyToClipboard, toast } from '../toast'
import StatusDot from '../components/StatusDot.vue'

const allowlistText = ref('')
const currentClientIP = ref('')
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
const errMsg = ref('')

async function load() {
  const [sec, aud] = await Promise.all([api('/api/v1/system/security'), api('/api/v1/audit')])
  allowlistText.value = (sec.allowlist || []).join('\n')
  currentClientIP.value = sec.current_client_ip || ''
  retentionDays.value = sec.retention_days || 14
  if (sec.expires_at_ms > 0) {
    expiresDate.value = new Date(sec.expires_at_ms).toISOString().slice(0, 16)
  }
  auditLogs.value = aud.logs || []
}

function addCurrentIP() {
  if (!currentClientIP.value) return
  const lines = allowlistText.value.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean)
  if (!lines.includes(currentClientIP.value)) {
    lines.push(currentClientIP.value)
    allowlistText.value = lines.join('\n')
  }
}

async function saveSecurity() {
  errMsg.value = ''
  try {
    const cidrs = allowlistText.value.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean)
    const expMs = expiresDate.value ? new Date(expiresDate.value).getTime() : 0
    await api('/api/v1/system/security', {
      method: 'PUT',
      body: JSON.stringify({ allowlist: cidrs, expires_at_ms: expMs, retention_days: retentionDays.value })
    })
    toast.success(t('msgSecuritySaved'))
    await load()
  } catch (e: any) {
    errMsg.value = e.message
    toast.error(e.message)
  }
}

async function changePassword() {
  errMsg.value = ''
  try {
    await api('/api/v1/auth/password', {
      method: 'POST',
      body: JSON.stringify({ current_password: curPass.value, new_password: newPass.value })
    })
    curPass.value = ''
    newPass.value = ''
    toast.success(t('msgPassUpdated'))
  } catch (e: any) {
    errMsg.value = e.message
    toast.error(e.message)
  }
}

async function setupTOTP() {
  errMsg.value = ''
  try {
    const res = await api('/api/v1/auth/totp/setup', { method: 'POST' })
    totpSecret.value = res.secret
    totpURI.value = res.otpauth_uri
    totpQR.value = await QRCode.toDataURL(res.otpauth_uri, {
      width: 184,
      margin: 2,
      color: { dark: '#09090b', light: '#ffffff' }
    })
  } catch (e: any) {
    errMsg.value = e.message
    toast.error(e.message)
  }
}

async function copyTotpSecret() {
  if (!totpSecret.value) return
  if (await copyToClipboard(totpSecret.value)) {
    copiedSecret.value = true
    toast.success(t('btnCopied'))
    setTimeout(() => {
      copiedSecret.value = false
    }, 1500)
  }
}

async function enableTOTP() {
  errMsg.value = ''
  try {
    await api('/api/v1/auth/totp/enable', { method: 'POST', body: JSON.stringify({ code: totpCode.value }) })
    toast.success(t('msgTotpEnabled'))
    totpCode.value = ''
    totpSecret.value = ''
    totpURI.value = ''
    totpQR.value = ''
  } catch (e: any) {
    errMsg.value = e.message
    toast.error(e.message)
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
    <div class="page-header">
      <h2 class="page-title">{{ t('navSecurity') }}</h2>
      <div class="row" style="gap: 8px;">
        <a href="/metrics" target="_blank" class="btn btn-secondary btn-sm" style="text-decoration: none;">
          <ExternalLink :size="13" />
          <span>{{ t('metricsLink') }}</span>
        </a>
        <button class="btn btn-secondary btn-sm" @click="downloadSignoff">
          <Download :size="13" />
          <span>{{ t('exportSignoff') }}</span>
        </button>
      </div>
    </div>

    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>

    <div class="grid-2">
      <div class="card">
        <h3>{{ t('accessControl') }}</h3>
        <div class="field">
          <div class="row" style="margin-bottom: 5px;">
            <label style="margin: 0;">{{ t('allowlistLabel') }}</label>
            <div class="spacer"></div>
            <button v-if="currentClientIP" class="btn btn-ghost btn-sm" type="button" @click="addCurrentIP">
              <Plus :size="12" />
              <span>{{ t('currentClientIpLabel') }}{{ currentClientIP }}</span>
            </button>
          </div>
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
          <button class="btn btn-secondary" @click="changePassword">
            <KeyRound :size="14" />
            <span>{{ t('btnChangePass') }}</span>
          </button>
          <button class="btn btn-secondary" @click="setupTOTP">
            <ShieldCheck :size="14" />
            <span>{{ t('btnSetupTotp') }}</span>
          </button>
        </div>
        <div v-if="totpSecret" class="sub-card" style="margin-top: 4px;">
          <div style="display: flex; gap: 16px; align-items: flex-start; flex-wrap: wrap;">
            <div v-if="totpQR" style="background: #ffffff; padding: 8px; border-radius: 6px; border: 1px solid var(--border); flex-shrink: 0;">
              <img :src="totpQR" alt="TOTP QR Code" style="display: block; width: 164px; height: 164px;" />
            </div>
            <div style="flex: 1; min-width: 220px;">
              <div style="font-weight: 600; margin-bottom: 6px;">{{ t('totpScanHint') }}</div>
              <div class="muted" style="margin-bottom: 6px;">{{ t('totpManualFallback') }}</div>
              <div class="row" style="margin-bottom: 10px;">
                <span class="code-chip">{{ totpSecret }}</span>
                <button class="btn btn-secondary btn-sm" @click="copyTotpSecret">
                  <Copy :size="12" />
                  <span>{{ copiedSecret ? t('btnCopied') : t('btnCopySecret') }}</span>
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

    <div class="card card-flush">
      <div class="card-header">
        <h3>{{ t('auditLogTitle') }}</h3>
      </div>
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
            <td class="muted">{{ fmtDateTime(l.ts_ms) }}</td>
            <td>{{ l.operator }}</td>
            <td><span class="code-chip">{{ l.remote_ip }}</span></td>
            <td><span class="code-chip">{{ l.action }}</span></td>
            <td>{{ l.target }}</td>
            <td>
              <StatusDot :state="l.status === 'PASS' ? 'ok' : 'critical'" :label="l.status === 'PASS' ? t('resPass') : t('resFail')" />
            </td>
            <td class="muted" style="max-width: 280px; word-break: break-all;"><code>{{ l.detail_json }}</code></td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
