<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api } from './api'
import DashboardView from './views/DashboardView.vue'
import DiagnosticsView from './views/DiagnosticsView.vue'
import SitesConfigView from './views/SitesConfigView.vue'
import PeerExportView from './views/PeerExportView.vue'
import FailoverView from './views/FailoverView.vue'
import AlertsView from './views/AlertsView.vue'
import SecurityAuditView from './views/SecurityAuditView.vue'

const user = ref<any>(null)
const checking = ref(true)
const activeTab = ref('dashboard')
const diagSite = ref('ob-venue-1')

const username = ref('admin')
const password = ref('')
const totpCode = ref('')
const loginErr = ref('')

const navItems = [
  { id: 'dashboard', label: '概览' },
  { id: 'config', label: 'VPN 通道' },
  { id: 'diagnostics', label: '链路监控' },
  { id: 'export', label: '配置导出' },
  { id: 'failover', label: '主备切换' },
  { id: 'alerts', label: '告警管理' },
  { id: 'security', label: '系统设置' }
]

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
  if (site) diagSite.value = site
  activeTab.value = tab
}

onMounted(checkAuth)
</script>

<template>
  <div v-if="checking" class="login-wrap">
    <div class="muted">加载中...</div>
  </div>

  <div v-else-if="!user" class="login-wrap">
    <div class="login-card">
      <h2 style="margin: 0 0 6px;">VPN 网关控制台</h2>
      <div class="muted" style="margin-bottom: 18px;">event-ipsec-hub</div>
      <div v-if="loginErr" class="alert-banner alert-critical">{{ loginErr }}</div>
      <div class="field">
        <label>账号</label>
        <input v-model="username" class="input" @keyup.enter="login" />
      </div>
      <div class="field">
        <label>密码</label>
        <input v-model="password" type="password" class="input" @keyup.enter="login" />
      </div>
      <div class="field">
        <label>动态验证码（未开启可留空）</label>
        <input v-model="totpCode" class="input" placeholder="6 位数字" @keyup.enter="login" />
      </div>
      <button class="btn" style="width: 100%; margin-top: 6px;" @click="login">登录</button>
    </div>
  </div>

  <div v-else class="layout">
    <aside class="sidebar">
      <div class="brand">
        <h1>VPN 网关</h1>
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
        {{ user.username }} · {{ user.role === 'admin' ? '管理员' : '只读' }}
        <div v-if="user.must_change_password" style="color: #fbbf24; margin-top: 4px;">
          请前往「系统设置」修改初始密码
        </div>
      </div>
    </aside>

    <div class="main">
      <header class="topbar">
        <div class="row">
          <strong style="font-size: 14px;">{{ navItems.find((n) => n.id === activeTab)?.label }}</strong>
          <span v-if="user.demo_mode" class="pill pill-warn">演示环境</span>
        </div>
        <div class="row">
          <a href="/metrics" target="_blank" class="muted" style="text-decoration: none;">Prometheus 指标</a>
          <button class="btn btn-secondary" @click="logout">退出</button>
        </div>
      </header>

      <main class="content">
        <DashboardView v-if="activeTab === 'dashboard'" @navigate="navigate" />
        <SitesConfigView v-else-if="activeTab === 'config'" />
        <DiagnosticsView v-else-if="activeTab === 'diagnostics'" :initial-site="diagSite" />
        <PeerExportView v-else-if="activeTab === 'export'" />
        <FailoverView v-else-if="activeTab === 'failover'" />
        <AlertsView v-else-if="activeTab === 'alerts'" />
        <SecurityAuditView v-else-if="activeTab === 'security'" />
      </main>
    </div>
  </div>
</template>
