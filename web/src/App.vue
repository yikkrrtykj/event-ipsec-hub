<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  Activity,
  ArrowLeftRight,
  Bell,
  FileOutput,
  GitCompareArrows,
  Languages,
  LayoutGrid,
  LogOut,
  Moon,
  ScrollText,
  Settings,
  Shield,
  Sun
} from 'lucide-vue-next'
import { api } from './api'
import { lang, t, toggleLang } from './i18n'
import { theme, toggleTheme } from './theme'
import ToastHost from './components/ToastHost.vue'
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
const diagSite = ref('')
const diagFocusTs = ref<number | null>(null)
const eventSite = ref('')
const exportSite = ref('')

const username = ref('admin')
const password = ref('')
const totpCode = ref('')
const loginErr = ref('')

const navIcons: Record<string, any> = {
  dashboard: LayoutGrid,
  config: ArrowLeftRight,
  export: FileOutput,
  diagnostics: Activity,
  events: ScrollText,
  failover: GitCompareArrows,
  alerts: Bell,
  security: Settings
}

const navGroups = computed(() => [
  {
    title: t('navGroupGateway'),
    items: [
      { id: 'dashboard', label: t('navDashboard') },
      { id: 'config', label: t('navConfig') },
      { id: 'export', label: t('navExport') }
    ]
  },
  {
    title: t('navGroupOps'),
    items: [
      { id: 'diagnostics', label: t('navDiagnostics') },
      { id: 'events', label: t('navEvents') },
      { id: 'failover', label: t('navFailover') },
      { id: 'alerts', label: t('navAlerts') }
    ]
  },
  {
    title: t('navGroupSystem'),
    items: [{ id: 'security', label: t('navSecurity') }]
  }
])

const activeLabel = computed(() => {
  for (const g of navGroups.value) {
    const hit = g.items.find((i) => i.id === activeTab.value)
    if (hit) return hit.label
  }
  return ''
})

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

function selectTab(id: string) {
  if (id === 'diagnostics') diagFocusTs.value = null
  if (id === 'events') eventSite.value = ''
  activeTab.value = id
}

function navigate(tab: string, site?: string, focusTsMs?: number) {
  if (tab === 'diagnostics') {
    if (site) diagSite.value = site
    diagFocusTs.value = focusTsMs ?? null
  } else if (tab === 'events') {
    eventSite.value = site || ''
  } else if (tab === 'export') {
    exportSite.value = site || ''
  }
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
      <div class="row" style="margin-bottom: 18px;">
        <div class="brand-mark">
          <Shield :size="16" :stroke-width="2" />
        </div>
        <div>
          <h2 style="margin: 0; font-size: 16px; font-weight: 650;">{{ t('consoleTitle') }}</h2>
          <div class="muted" style="font-size: 11.5px; font-family: ui-monospace, monospace;">event-ipsec-hub</div>
        </div>
        <div class="spacer"></div>
        <button class="btn btn-secondary btn-icon" :title="t('switchThemeTitle')" @click="toggleTheme">
          <Sun v-if="theme === 'dark'" :size="15" />
          <Moon v-else :size="15" />
        </button>
        <button class="btn btn-secondary btn-sm" @click="toggleLang">
          {{ lang === 'zh' ? 'EN' : '中文' }}
        </button>
      </div>
      <div v-if="loginErr" class="alert-banner alert-critical">{{ loginErr }}</div>
      <div class="field">
        <label>{{ t('username') }}</label>
        <input v-model="username" class="input" autocomplete="username" @keyup.enter="login" />
      </div>
      <div class="field">
        <label>{{ t('password') }}</label>
        <input v-model="password" type="password" class="input" autocomplete="current-password" @keyup.enter="login" />
      </div>
      <div class="field">
        <label>{{ t('totpLabel') }}</label>
        <input v-model="totpCode" class="input" :placeholder="t('totpPlaceholder')" inputmode="numeric" @keyup.enter="login" />
      </div>
      <button class="btn" style="width: 100%; margin-top: 6px; padding: 9px 14px;" @click="login">{{ t('loginBtn') }}</button>
    </div>
  </div>

  <div v-else class="layout">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark">
          <Shield :size="16" :stroke-width="2" />
        </div>
        <div>
          <h1>{{ t('brandTitle') }}</h1>
          <span>event-ipsec-hub</span>
        </div>
      </div>

      <template v-for="group in navGroups" :key="group.title">
        <div class="nav-group">{{ group.title }}</div>
        <button
          v-for="item in group.items"
          :key="item.id"
          class="nav-btn"
          :class="{ active: activeTab === item.id }"
          @click="selectTab(item.id)"
        >
          <component :is="navIcons[item.id]" :size="16" :stroke-width="1.75" />
          <span>{{ item.label }}</span>
        </button>
      </template>

      <div class="spacer"></div>
      <div class="sidebar-footer">
        <div style="font-weight: 500; color: var(--text-main);">{{ user.username }} · {{ user.role === 'admin' ? t('roleAdmin') : t('roleReadonly') }}</div>
        <div v-if="user.must_change_password" style="color: var(--warn-fg); margin-top: 4px; font-size: 11.5px;">
          {{ t('mustChangePass') }}
        </div>
      </div>
    </aside>

    <div class="main">
      <header class="topbar">
        <div class="row">
          <strong style="font-size: 14.5px; font-weight: 600;">{{ activeLabel }}</strong>
          <span v-if="user.demo_mode" class="pill pill-warn">{{ t('demoEnv') }}</span>
        </div>
        <div class="row" style="gap: 8px;">
          <button class="btn btn-secondary btn-icon" :title="t('switchThemeTitle')" @click="toggleTheme">
            <Sun v-if="theme === 'dark'" :size="15" />
            <Moon v-else :size="15" />
          </button>
          <button class="btn btn-secondary btn-sm" @click="toggleLang">
            <Languages :size="14" />
            <span>{{ lang === 'zh' ? 'English' : '中文' }}</span>
          </button>
          <button class="btn btn-secondary btn-sm" @click="logout">
            <LogOut :size="14" />
            <span>{{ t('logout') }}</span>
          </button>
        </div>
      </header>

      <main class="content">
        <DashboardView v-if="activeTab === 'dashboard'" @navigate="navigate" />
        <SitesConfigView v-else-if="activeTab === 'config'" @navigate="navigate" />
        <DiagnosticsView
          v-else-if="activeTab === 'diagnostics'"
          :initial-site="diagSite"
          :focus-ts-ms="diagFocusTs"
          @navigate="navigate"
        />
        <EventsView v-else-if="activeTab === 'events'" :initial-site="eventSite" @navigate="navigate" />
        <PeerExportView v-else-if="activeTab === 'export'" :initial-site="exportSite" />
        <FailoverView v-else-if="activeTab === 'failover'" />
        <AlertsView v-else-if="activeTab === 'alerts'" />
        <SecurityAuditView v-else-if="activeTab === 'security'" />
      </main>
    </div>
  </div>

  <ToastHost />
</template>
