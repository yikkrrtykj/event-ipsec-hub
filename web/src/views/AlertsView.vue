<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, fmtDateTime } from '../api'
import { alertStatusLabel, sourceLabel, t } from '../i18n'

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
    msg.value = t('msgRuleSaved', { name: rule.name })
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
    msg.value = t('msgFeishuSent')
  } catch (e: any) {
    errMsg.value = e.message
  }
}

onMounted(load)
</script>

<template>
  <div>
    <h2 style="margin: 0 0 14px; font-size: 18px;">{{ t('navAlerts') }}</h2>
    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>
    <div v-if="msg" class="alert-banner alert-ok">{{ msg }}</div>

    <div class="card">
      <h3>{{ t('feishuTitle') }}</h3>
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
      <button class="btn" @click="testFeishu">{{ t('btnSendTest') }}</button>
    </div>

    <div class="card">
      <h3>{{ t('alertRulesTitle') }}</h3>
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
            <td><strong>{{ r.name }}</strong></td>
            <td><code>{{ r.metric }}</code></td>
            <td><input v-model.number="r.threshold" type="number" step="0.01" class="input" style="width: 90px;" /></td>
            <td><input v-model.number="r.cooldown_seconds" type="number" class="input" style="width: 85px;" /></td>
            <td>
              <span class="pill" :class="r.severity === 'critical' ? 'pill-critical' : 'pill-warn'">
                {{ r.severity === 'critical' ? t('sevCritical') : t('sevWarning') }}
              </span>
            </td>
            <td><button class="btn btn-secondary" @click="saveRule(r)">{{ t('btnSaveShort') }}</button></td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <h3>{{ t('alertHistoryTitle') }}</h3>
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
            <td>{{ fmtDateTime(h.ts_ms) }}</td>
            <td>
              <span class="pill" :class="h.status === 'FIRING' ? 'pill-critical' : h.status === 'RECOVERED' ? 'pill-ok' : 'pill-warn'">
                {{ alertStatusLabel(h.status) }}
              </span>
            </td>
            <td>{{ h.alert_name }}</td>
            <td>{{ sourceLabel(h.source) }}</td>
            <td>{{ h.site_id }}</td>
            <td><code>{{ h.root_cause }}</code></td>
            <td>{{ h.delivered ? t('deliveredOk') : h.error || t('notConfigured') }}</td>
          </tr>
        </tbody>
      </table>
      <div v-else class="muted">{{ t('noAlertHistory') }}</div>
    </div>
  </div>
</template>
