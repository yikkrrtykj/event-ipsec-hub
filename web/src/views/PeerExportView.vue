<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { api, downloadTextFile } from '../api'

const profiles = ref<any[]>([])
const profileId = ref('')
const availableSites = ref<string[]>([])
const siteId = ref('ob-venue-1')
const format = ref('tencent-json')
const includePSK = ref(false)
const confirmPassword = ref('')
const filename = ref('')
const content = ref('')
const errMsg = ref('')
const copied = ref(false)

async function load() {
  const res = await api('/api/v1/profiles')
  profiles.value = res.profiles || []
  if (profiles.value.length) {
    profileId.value = profiles.value[0].id
  }
}

async function refreshSites() {
  const rec = profiles.value.find((p) => p.id === profileId.value)
  if (!rec) return
  try {
    const res = await api('/api/v1/profiles/validate', {
      method: 'POST',
      body: JSON.stringify({ yaml_content: rec.yaml_content })
    })
    availableSites.value = (res.sites || []).map((s: any) => s.id)
    if (availableSites.value.length && !availableSites.value.includes(siteId.value)) {
      siteId.value = availableSites.value[0]
    }
  } catch {
    availableSites.value = []
  }
}

watch(profileId, refreshSites)

async function generate() {
  errMsg.value = ''
  copied.value = false
  try {
    const res = await api(`/api/v1/profiles/${encodeURIComponent(profileId.value)}/export-peer`, {
      method: 'POST',
      body: JSON.stringify({
        site_id: siteId.value,
        format: format.value,
        include_psk: includePSK.value,
        confirm_password: confirmPassword.value
      })
    })
    filename.value = res.filename
    content.value = res.content
    confirmPassword.value = ''
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function copyText() {
  if (!content.value) return
  await navigator.clipboard.writeText(content.value)
  copied.value = true
  setTimeout(() => (copied.value = false), 2000)
}

onMounted(load)
</script>

<template>
  <div>
    <h2 style="margin: 0 0 14px; font-size: 18px;">配置导出</h2>
    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>

    <div class="card">
      <div class="grid-3">
        <div class="field">
          <label>配置集</label>
          <select v-model="profileId" class="select">
            <option v-for="p in profiles" :key="p.id" :value="p.id">{{ p.id }} ({{ p.name }})</option>
          </select>
        </div>
        <div class="field">
          <label>对端站点</label>
          <select v-if="availableSites.length" v-model="siteId" class="select">
            <option v-for="id in availableSites" :key="id" :value="id">{{ id }}</option>
          </select>
          <input v-else v-model="siteId" class="input" placeholder="如 ob-venue-1" />
        </div>
        <div class="field">
          <label>导出格式</label>
          <select v-model="format" class="select">
            <option value="tencent-json">腾讯云格式 JSON (IKEv2)</option>
            <option value="hillstone-md">山石防火墙参数单 (Markdown)</option>
            <option value="generic-md">通用参数单 (Markdown)</option>
            <option value="hillstone-draft">山石 CLI 参考配置</option>
            <option value="strongswan-draft">strongSwan 参考配置</option>
          </select>
        </div>
      </div>

      <div class="row" style="margin-top: 8px; padding-top: 10px; border-top: 1px solid var(--border);">
        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
          <input type="checkbox" v-model="includePSK" />
          <span>包含预共享密钥明文</span>
          <span class="muted">（默认隐藏为 <code>&lt;SEND_SEPARATELY&gt;</code>，导出明文将记入操作日志）</span>
        </label>
        <input
          v-if="includePSK"
          v-model="confirmPassword"
          type="password"
          class="input"
          style="width: 200px;"
          placeholder="输入管理员密码确认"
        />
        <div class="spacer"></div>
        <button class="btn" @click="generate">生成配置</button>
      </div>
    </div>

    <div v-if="content" class="card">
      <div class="row" style="margin-bottom: 10px;">
        <strong>{{ filename }}</strong>
        <div class="spacer"></div>
        <button class="btn btn-secondary" @click="copyText">{{ copied ? '已复制' : '复制内容' }}</button>
        <button class="btn btn-ok" @click="downloadTextFile(filename, content)">下载文件</button>
      </div>
      <div class="code-block">{{ content }}</div>
    </div>
  </div>
</template>
