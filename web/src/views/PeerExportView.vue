<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, downloadTextFile } from '../api'

const profiles = ref<any[]>([])
const profileId = ref('')
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
    <h2 style="margin: 0 0 14px;">对端防火墙配置一键导出（发给对端网工直接照填）</h2>
    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>

    <div class="card">
      <div class="grid-3">
        <div class="field">
          <label>选择赛事 Profile</label>
          <select v-model="profileId" class="select">
            <option v-for="p in profiles" :key="p.id" :value="p.id">{{ p.id }} ({{ p.name }})</option>
          </select>
        </div>
        <div class="field">
          <label>接收方站点 ID</label>
          <input v-model="siteId" class="input" placeholder="如 ob-venue-1 / server-core" />
        </div>
        <div class="field">
          <label>导出交付格式</label>
          <select v-model="format" class="select">
            <option value="tencent-json">腾讯云 VPN 网关同款精简 JSON（强加密 IKEv2）</option>
            <option value="hillstone-md">山石 Hillstone / StoneOS 参数单 (Markdown)</option>
            <option value="generic-md">厂商中立通用参数单 (Markdown)</option>
            <option value="hillstone-draft">山石 StoneOS 参考 CLI 草稿</option>
            <option value="strongswan-draft">strongSwan swanctl.conf 参考草稿</option>
          </select>
        </div>
      </div>

      <div class="row" style="margin-top: 8px; padding-top: 10px; border-top: 1px solid var(--border);">
        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
          <input type="checkbox" v-model="includePSK" />
          <span>包含明文 PSK 一次性交付（默认脱敏 <code>&lt;SEND_SEPARATELY&gt;</code>，开启将二次验密并记审计）</span>
        </label>
        <input
          v-if="includePSK"
          v-model="confirmPassword"
          type="password"
          class="input"
          style="width: 220px;"
          placeholder="请输入管理员密码确认"
        />
        <div class="spacer"></div>
        <button class="btn" @click="generate">一键生成对端配置</button>
      </div>
    </div>

    <div v-if="content" class="card">
      <div class="row" style="margin-bottom: 10px;">
        <strong>{{ filename }}</strong>
        <div class="spacer"></div>
        <button class="btn btn-secondary" @click="copyText">{{ copied ? '已复制 ✓' : '复制全文' }}</button>
        <button class="btn btn-ok" @click="downloadTextFile(filename, content)">下载文件发送给对端</button>
      </div>
      <div class="code-block">{{ content }}</div>
    </div>
  </div>
</template>
