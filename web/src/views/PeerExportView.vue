<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { Copy, Download, FileCode2 } from 'lucide-vue-next'
import { api, downloadTextFile } from '../api'
import { t } from '../i18n'
import { copyToClipboard, toast } from '../toast'

const props = defineProps<{ initialSite?: string }>()

const profiles = ref<any[]>([])
const profileId = ref('')
const availableSites = ref<string[]>([])
const siteId = ref(props.initialSite || '')
const format = ref('hillstone-md')
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
watch(() => props.initialSite, (v) => {
  if (v) siteId.value = v
})

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
    toast.success(res.filename)
  } catch (e: any) {
    errMsg.value = e.message
    toast.error(e.message)
  }
}

async function copyText() {
  if (!content.value) return
  if (await copyToClipboard(content.value)) {
    copied.value = true
    toast.success(t('btnCopied'))
    setTimeout(() => (copied.value = false), 1800)
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="page-header">
      <h2 class="page-title">{{ t('navExport') }}</h2>
    </div>
    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>

    <div class="card">
      <div class="grid-3">
        <div class="field">
          <label>{{ t('profileSet') }}</label>
          <select v-model="profileId" class="select">
            <option v-for="p in profiles" :key="p.id" :value="p.id">{{ p.id }} ({{ p.name }})</option>
          </select>
        </div>
        <div class="field">
          <label>{{ t('colPeerSite') }}</label>
          <select v-if="availableSites.length" v-model="siteId" class="select">
            <option v-for="id in availableSites" :key="id" :value="id">{{ id }}</option>
          </select>
          <input v-else v-model="siteId" class="input" placeholder="venue-1" />
        </div>
        <div class="field">
          <label>{{ t('exportFormat') }}</label>
          <select v-model="format" class="select">
            <option value="hillstone-md">{{ t('fmtHillstoneMd') }}</option>
            <option value="hillstone-draft">{{ t('fmtHillstoneCli') }}</option>
            <option value="tencent-json">{{ t('fmtStandardJson') }}</option>
            <option value="generic-md">{{ t('fmtGenericMd') }}</option>
            <option value="strongswan-draft">{{ t('fmtStrongswan') }}</option>
          </select>
        </div>
      </div>

      <div class="row" style="margin-top: 8px; padding-top: 12px; border-top: 1px solid var(--border);">
        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
          <input type="checkbox" v-model="includePSK" />
          <span>{{ t('includePskPlain') }}</span>
          <span class="muted">({{ t('includePskHint') }})</span>
        </label>
        <input
          v-if="includePSK"
          v-model="confirmPassword"
          type="password"
          class="input"
          style="width: 200px;"
          :placeholder="t('confirmAdminPassPh')"
        />
        <div class="spacer"></div>
        <button class="btn" :disabled="!profileId || !siteId" @click="generate">
          <FileCode2 :size="14" />
          <span>{{ t('btnGenerateCfg') }}</span>
        </button>
      </div>
    </div>

    <div v-if="content" class="card">
      <div class="row" style="margin-bottom: 12px;">
        <span class="code-chip">{{ filename }}</span>
        <div class="spacer"></div>
        <button class="btn btn-secondary btn-sm" @click="copyText">
          <Copy :size="13" />
          <span>{{ copied ? t('btnCopied') : t('btnCopy') }}</span>
        </button>
        <button class="btn btn-sm" @click="downloadTextFile(filename, content)">
          <Download :size="13" />
          <span>{{ t('btnDownload') }}</span>
        </button>
      </div>
      <div class="code-block" style="max-height: 480px;">{{ content }}</div>
    </div>
  </div>
</template>
