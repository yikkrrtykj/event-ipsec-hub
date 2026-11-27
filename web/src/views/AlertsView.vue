<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { Send } from 'lucide-vue-next'
import { api, fmtDateTime } from '../api'
import { alertMetricMeta, alertRuleNameLabel, alertStatusLabel, causeLabel, sourceLabel, t } from '../i18n'
import { toast } from '../toast'
import StatusDot from '../components/StatusDot.vue'

const rules = ref<any[]>([])
const history = ref<any[]>([])
const channelMeta = ref<{ configured: boolean; enabled: boolean; masked_url: string; has_secret: boolean }>({
  configured: false,
  enabled: false,
  masked_url: '',
  has_secret: false
})
const feishuEnabled = ref(true)
const feishuURL = ref('')
const feishuSecret = ref('')
const errMsg = ref('')

async function load() {
  const [r1, r2, r3] = await Promise.all([
    api('/api/v1/alerts/rules'),
    api('/api/v1/alerts/history'),
    api('/api/v1/alerts/channel')
  ])
  rules.value = r1.rules || []
  history.value = r2.history || []
  channelMeta.value = {
    configured: Boolean(r3.configured),
    enabled: Boolean(r3.enabled),
    masked_url: r3.masked_url || '',
    has_secret: Boolean(r3.has_secret)
  }
  if (channelMeta.value.configured) {
    feishuEnabled.value = channelMeta.value.enabled
  }
}

async function saveChannel() {
  errMsg.value = ''
  try {
    const res = await api('/api/v1/alerts/channel', {
      method: 'PUT',
      body: JSON.stringify({
        enabled: feishuEnabled.value,
        webhook_url: feishuURL.value.trim(),
        secret: feishuSecret.value,
        keep_secret: feishuSecret.value === ''
      })
    })
    channelMeta.value = {
      configured: Boolean(res.configured),
      enabled: Boolean(res.enabled),
      masked_url: res.masked_url || '',
      has_secret: Boolean(res.has_secret)
    }
    feishuURL.value = ''
    feishuSecret.value = ''
    toast.success(t('msgChannelSaved'))
  } catch (e: any) {
    errMsg.value = e.message
    toast.error(e.message)
  }
}

async function saveRule(rule: any) {
  errMsg.value = ''
  try {
    await api('/api/v1/alerts/rules', { method: 'PUT', body: JSON.stringify(rule) })
    toast.success(t('msgRuleSaved', { name: alertRuleNameLabel(rule.name) }))
  } catch (e: any) {
    errMsg.value = e.message
    toast.error(e.message)
  }
}

function displayThreshold(rule: any): number {
  const m = alertMetricMeta(rule.metric)
  if (m.isPercent) {
    return Math.round((Number(rule.threshold) || 0) * 10000) / 100
  }
  return Number(rule.threshold) || 0
}

function updateThreshold(rule: any, rawVal: string) {
  const num = Number(rawVal)
  if (!Number.isFinite(num)) return
  const m = alertMetricMeta(rule.metric)
  rule.threshold = m.isPercent ? Math.max(0, Math.min(1, Number((num / 100).toFixed(4)))) : num
}

async function testFeishu() {
  errMsg.value = ''
  try {
    await api('/api/v1/alerts/feishu/test', {
      method: 'POST',
      body: JSON.stringify({ webhook_url: feishuURL.value.trim(), secret: feishuSecret.value })
    })
    toast.success(t('msgFeishuSent'))
  } catch (e: any) {
    errMsg.value = e.message
    toast.error(e.message)
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="page-header">
      <h2 class="page-title">{{ t('navAlerts') }}</h2>
    </div>
    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>

    <div class="card">
      <div class="row" style="margin-bottom: 12px;">
        <h3 style="margin: 0;">{{ t('feishuTitle') }}</h3>
        <StatusDot
          :state="channelMeta.configured && channelMeta.enabled ? 'ok' : 'unknown'"
          :label="channelMeta.configured ? t('feishuConfigured') : t('feishuNotConfigured')"
        />
        <span v-if="channelMeta.masked_url" class="code-chip">{{ channelMeta.masked_url }}</span>
      </div>
      <div v-if="channelMeta.configured" class="muted" style="margin-bottom: 10px;">
        {{ t('feishuLeaveBlankHint') }}
      </div>
      <div class="grid-2">
        <div class="field">
          <label>{{ t('webhookUrl') }}</label>
          <input v-model="feishuURL" class="input" placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..." />
        </div>
        <div class="field">
          <label>{{ t('signSecret') }}</label>
          <input v-model="feishuSecret" type="password" class="input" :placeholder="t('signSecretPh')" />
        </div>
      </div>
      <div class="row">
        <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
          <input type="checkbox" v-model="feishuEnabled" />
          <span>{{ t('feishuEnabledCb') }}</span>
        </label>
        <div class="spacer"></div>
        <button class="btn btn-secondary" @click="testFeishu">
          <Send :size="13" />
          <span>{{ t('btnSendTest') }}</span>
        </button>
        <button class="btn" @click="saveChannel">{{ t('btnSaveChannel') }}</button>
      </div>
    </div>

    <div class="card card-flush">
      <div class="card-header">
        <h3>{{ t('alertRulesTitle') }}</h3>
      </div>
      <table class="table">
        <thead>
          <tr>
            <th>{{ t('colEnabled') }}</th>
            <th>{{ t('colRuleName') }}</th>
            <th>{{ t('colMetric') }}</th>
            <th>{{ t('colThreshold') }}</th>
            <th>{{ t('colCooldown') }}</th>
            <th>{{ t('colSeverity') }}</th>
            <th>{{ t('colAction') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in rules" :key="r.id">
            <td><input type="checkbox" v-model="r.enabled" /></td>
            <td>
              <div style="font-weight: 600;">{{ alertRuleNameLabel(r.name) }}</div>
              <div class="muted" style="font-size: 11px;"><code>{{ r.name }}</code></div>
            </td>
            <td>{{ alertMetricMeta(r.metric).label }}</td>
            <td>
              <span v-if="alertMetricMeta(r.metric).isBinaryState" class="pill pill-unknown">{{ t('triggerOnDown') }}</span>
              <div v-else class="row" style="gap: 6px;">
                <input
                  :value="displayThreshold(r)"
                  type="number"
                  step="1"
                  class="input"
                  style="width: 78px;"
                  @input="updateThreshold(r, ($event.target as HTMLInputElement).value)"
                />
                <span v-if="alertMetricMeta(r.metric).unit" class="muted">{{ alertMetricMeta(r.metric).unit }}</span>
              </div>
            </td>
            <td><input v-model.number="r.cooldown_seconds" type="number" class="input" style="width: 82px;" /></td>
            <td>
              <StatusDot
                :state="r.severity === 'critical' ? 'critical' : 'warn'"
                :label="r.severity === 'critical' ? t('sevCritical') : t('sevWarning')"
              />
            </td>
            <td><button class="btn btn-secondary btn-sm" @click="saveRule(r)">{{ t('btnSaveShort') }}</button></td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card card-flush">
      <div class="card-header">
        <h3>{{ t('alertHistoryTitle') }}</h3>
      </div>
      <table v-if="history.length" class="table">
        <thead>
          <tr>
            <th>{{ t('colTime') }}</th>
            <th>{{ t('colStatus') }}</th>
            <th>{{ t('colRule') }}</th>
            <th>{{ t('colSource') }}</th>
            <th>{{ t('colSite') }}</th>
            <th>{{ t('colDiagCode') }}</th>
            <th>{{ t('colDelivery') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="h in history" :key="h.id">
            <td class="muted">{{ fmtDateTime(h.ts_ms) }}</td>
            <td>
              <StatusDot
                :state="h.status === 'FIRING' ? 'critical' : h.status === 'RECOVERED' ? 'ok' : 'warn'"
                :label="alertStatusLabel(h.status)"
              />
            </td>
            <td style="font-weight: 500;">{{ alertRuleNameLabel(h.alert_name) }}</td>
            <td class="muted">{{ sourceLabel(h.source) }}</td>
            <td><span class="code-chip">{{ h.site_id || '-' }}</span></td>
            <td>
              <span>{{ causeLabel(h.root_cause) }}</span>
              <div v-if="h.root_cause" class="muted" style="font-size: 11px;"><code>{{ h.root_cause }}</code></div>
            </td>
            <td class="muted">{{ h.delivered ? t('deliveredOk') : h.error || t('notConfigured') }}</td>
          </tr>
        </tbody>
      </table>
      <div v-else class="muted" style="padding: 20px;">{{ t('noAlertHistory') }}</div>
    </div>
  </div>
</template>
