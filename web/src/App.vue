<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api } from './api'
import { lang, t, toggleLang } from './i18n'
import DashboardView from './views/DashboardView.vue'
import DiagnosticsView from './views/DiagnosticsView.vue'
import EventsView from './views/EventsView.vue'
import SitesConfigView from './views/SitesConfigView.vue'
import PeerExportView from './views/PeerExportView.vue'
import FailoverView from './views/FailoverView.vue'
import AlertsView from './views/AlertsView.vue'
import SecurityAuditView from './views/SecurityAuditView.vue'

const user = ref<any>(null)
const checking = ref(true)
const activeTab = ref('dashboard')
const diagSite = ref('ob-venue-1')
const eventSite = ref('')

const username = ref('admin')
const password = ref('')
const totpCode = ref('')
const loginErr = ref('')

const navItems = computed(() => [
  { id: 'dashboard', label: t('navDashboard') },
  { id: 'config', label: t('navConfig') },
  { id: 'diagnostics', label: t('navDiagnostics') },
  { id: 'events', label: t('navEvents') },
  { id: 'export', label: t('navExport') },
  { id: 'failover', label: t('navFailover') },
  { id: 'alerts', label: t('navAlerts') },
  { id: 'security', label: t('navSecurity') }
])

async function checkAuth() {
  checking.value = true
  try {
    user.value = await api('/api/v1/auth/me')
  } catch {
    user.value = null
  } finally {
    checking.value = false
  }
}

async function login() {
  loginErr.value = ''
  try {
    user.value = await api('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        username: username.value,
        password: password.value,
        totp_code: totpCode.value
      })
    })
    password.value = ''
    totpCode.value = ''
  } catch (e: any) {
    loginErr.value = e.message
  }
}

async function logout() {
  await api('/api/v1/auth/logout', { method: 'POST' }).catch(() => {})
  user.value = null
}

function navigate(tab: string, site?: string) {
  if (tab === 'diagnostics' && site) diagSite.value = site
  if (tab === 'events') eventSite.value = site || ''
  activeTab.value = tab
}

onMounted(checkAuth)
</script>

<template>
  <div v-if="checking" class="login-wrap">
    <div class="muted">{{ t('loading') }}</div>
  </div>

  <div v-else-if="!user" class="login-wrap">
    <div class="login-card">
      <div class="row" style="margin-bottom: 6px;">
        <h2 style="margin: 0;">{{ t('consoleTitle') }}</h2>
        <div class="spacer"></div>
        <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 12px;" @click="toggleLang">
          {{ lang === 'zh' ? 'EN' : '中文' }}
        </button>
      </div>
      <div class="muted" style="margin-bottom: 18px;">event-ipsec-hub</div>
      <div v-if="loginErr" class="alert-banner alert-critical">{{ loginErr }}</div>
      <div class="field">
        <label>{{ t('username') }}</label>
        <input v-model="username" class="input" @keyup.enter="login" />
      </div>
      <div class="field">
        <label>{{ t('password') }}</label>
        <input v-model="password" type="password" class="input" @keyup.enter="login" />
      </div>
      <div class="field">
        <label>{{ t('totpLabel') }}</label>
        <input v-model="totpCode" class="input" :placeholder="t('totpPlaceholder')" @keyup.enter="login" />
      </div>
      <button class="btn" style="width: 100%; margin-top: 6px;" @click="login">{{ t('loginBtn') }}</button>
    </div>
  </div>

  <div v-else class="layout">
    <aside class="sidebar">
      <div class="brand">
        <h1>{{ t('brandTitle') }}</h1>
        <span>event-ipsec-hub</span>
      </div>
      <button
        v-for="item in navItems"
        :key="item.id"
        class="nav-btn"
        :class="{ active: activeTab === item.id }"
        @click="activeTab = item.id"
      >
        {{ item.label }}
      </button>
      <div class="spacer"></div>
      <div class="muted" style="padding: 10px 8px; border-top: 1px solid var(--border);">
        {{ user.username }} · {{ user.role === 'admin' ? t('roleAdmin') : t('roleReadonly') }}
        <div v-if="user.must_change_password" style="color: #fbbf24; margin-top: 4px;">
          {{ t('mustChangePass') }}
        </div>
      </div>
    </aside>

    <div class="main">
      <header class="topbar">
        <div class="row">
          <strong style="font-size: 14px;">{{ navItems.find((n) => n.id === activeTab)?.label }}</strong>
          <span v-if="user.demo_mode" class="pill pill-warn">{{ t('demoEnv') }}</span>
        </div>
        <div class="row">
          <a href="/metrics" target="_blank" class="muted" style="text-decoration: none;">{{ t('metricsLink') }}</a>
          <button class="btn btn-secondary" @click="toggleLang">{{ lang === 'zh' ? 'English' : '中文' }}</button>
          <button class="btn btn-secondary" @click="logout">{{ t('logout') }}</button>
        </div>
      </header>

      <main class="content">
        <DashboardView v-if="activeTab === 'dashboard'" @navigate="navigate" />
        <SitesConfigView v-else-if="activeTab === 'config'" />
        <DiagnosticsView v-else-if="activeTab === 'diagnostics'" :initial-site="diagSite" @navigate="navigate" />
        <EventsView v-else-if="activeTab === 'events'" :initial-site="eventSite" @navigate="navigate" />
        <PeerExportView v-else-if="activeTab === 'export'" />
        <FailoverView v-else-if="activeTab === 'failover'" />
        <AlertsView v-else-if="activeTab === 'alerts'" />
        <SecurityAuditView v-else-if="activeTab === 'security'" />
      </main>
    </div>
  </div>
</template>
