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

// Login form
const username = ref('admin')
const password = ref('')
const totpCode = ref('')
const loginErr = ref('')

const navItems = [
  { id: 'dashboard', label: '网关运行总览' },
  { id: 'diagnostics', label: '四层同步排障' },
  { id: 'config', label: '站点与策略配置' },
  { id: 'export', label: '对端配置一键导出' },
  { id: 'failover', label: '主备门控与角色互换' },
  { id: 'alerts', label: '内置告警与飞书' },
  { id: 'security', label: '安全护栏与签收审计' }
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
    <div class="muted">正在连接 event-ipsec-hub V4 控制台...</div>
  </div>

  <div v-else-if="!user" class="login-wrap">
    <div class="login-card">
      <h2 style="margin: 0 0 6px;">event-ipsec-hub V4</h2>
      <div class="muted" style="margin-bottom: 18px;">自托管赛事 IPsec VPN 网关控制台（TLS 1.3 · 权限隔离）</div>
      <div v-if="loginErr" class="alert-banner alert-critical">{{ loginErr }}</div>
      <div class="field">
        <label>管理员账号</label>
        <input v-model="username" class="input" @keyup.enter="login" />
      </div>
      <div class="field">
        <label>密码</label>
        <input v-model="password" type="password" class="input" @keyup.enter="login" />
      </div>
      <div class="field">
        <label>TOTP 动态码（如已开启 2FA）</label>
        <input v-model="totpCode" class="input" placeholder="选填 6 位数字" @keyup.enter="login" />
      </div>
      <button class="btn" style="width: 100%; margin-top: 6px;" @click="login">登录控制台</button>
    </div>
  </div>

  <div v-else class="layout">
    <aside class="sidebar">
      <div class="brand">
        <h1>event-ipsec-hub</h1>
        <span>V4.0 · Go + strongSwan 网关</span>
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
        用户: {{ user.username }} ({{ user.role }})
        <div v-if="user.must_change_password" style="color: #fbbf24; margin-top: 4px;">
          请尽快前往「安全护栏」修改初始密码
        </div>
      </div>
    </aside>

    <div class="main">
      <header class="topbar">
        <div class="row">
          <span class="pill pill-info">强加密 IKEv2 · Linux XFRM</span>
          <span v-if="user.demo_mode" class="pill pill-warn">DEMO 预览模式</span>
        </div>
        <div class="row">
          <a href="/metrics" target="_blank" class="muted" style="text-decoration: none;">/metrics</a>
          <button class="btn btn-secondary" @click="logout">退出登录</button>
        </div>
      </header>

      <main class="content">
        <DashboardView v-if="activeTab === 'dashboard'" @navigate="navigate" />
        <DiagnosticsView v-else-if="activeTab === 'diagnostics'" :initial-site="diagSite" />
        <SitesConfigView v-else-if="activeTab === 'config'" />
        <PeerExportView v-else-if="activeTab === 'export'" />
        <FailoverView v-else-if="activeTab === 'failover'" />
        <AlertsView v-else-if="activeTab === 'alerts'" />
        <SecurityAuditView v-else-if="activeTab === 'security'" />
      </main>
    </div>
  </div>
</template>
