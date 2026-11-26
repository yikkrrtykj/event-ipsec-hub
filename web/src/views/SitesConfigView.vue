<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, fmtDateTime } from '../api'

const profiles = ref<any[]>([])
const secretsMeta = ref<any[]>([])
const selectedId = ref('')
const yamlText = ref('')
const hubRole = ref('primary')
const note = ref('')
const output = ref('')
const errMsg = ref('')
const revisions = ref<any[]>([])

// Write-only PSK rotation form
const secretSite = ref('')
const secretRef = ref('file:/etc/ipsecvpn/secrets/ob-venue-1.psk')
const secretPSK = ref('')

async function loadProfiles() {
  const res = await api('/api/v1/profiles')
  profiles.value = res.profiles || []
  secretsMeta.value = res.secrets_meta || []
  if (!selectedId.value && profiles.value.length) {
    selectProfile(profiles.value[0])
  }
}

async function selectProfile(p: any) {
  selectedId.value = p.id
  yamlText.value = p.yaml_content
  hubRole.value = p.hub_role || 'primary'
  const revs = await api(`/api/v1/profiles/${encodeURIComponent(p.id)}/revisions`)
  revisions.value = revs.revisions || []
}

async function validateYAML() {
  errMsg.value = ''
  try {
    const res = await api('/api/v1/profiles/validate', {
      method: 'POST',
      body: JSON.stringify({ yaml_content: yamlText.value })
    })
    output.value = JSON.stringify(res, null, 2)
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function saveProfile(activate = false) {
  errMsg.value = ''
  try {
    const res = await api('/api/v1/profiles', {
      method: 'POST',
      body: JSON.stringify({
        yaml_content: yamlText.value,
        hub_role: hubRole.value,
        note: note.value || 'Web update',
        activate
      })
    })
    output.value = JSON.stringify(res, null, 2)
    await loadProfiles()
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function renderPreview() {
  if (!selectedId.value) return
  errMsg.value = ''
  try {
    const res = await api(`/api/v1/profiles/${encodeURIComponent(selectedId.value)}/render`)
    output.value = `=== swanctl.conf ===\n${res.files['swanctl.conf'].preview}\n=== ipsecvpn.nft ===\n${res.files['ipsecvpn.nft'].preview}`
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function applyProfile(confirmed: boolean) {
  if (!selectedId.value) return
  errMsg.value = ''
  try {
    const res = await api(`/api/v1/profiles/${encodeURIComponent(selectedId.value)}/apply`, {
      method: 'POST',
      body: JSON.stringify({ confirmed, maintenance: false })
    })
    output.value = JSON.stringify(res, null, 2)
  } catch (e: any) {
    errMsg.value = e.message
  }
}

function randomHex64() {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  secretPSK.value = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

async function saveSecret() {
  if (!selectedId.value) return
  errMsg.value = ''
  try {
    const res = await api(`/api/v1/profiles/${encodeURIComponent(selectedId.value)}/secrets`, {
      method: 'POST',
      body: JSON.stringify({
        site_id: secretSite.value,
        secret_ref: secretRef.value,
        psk_hex: secretPSK.value
      })
    })
    secretPSK.value = ''
    output.value = '密钥已通过 root Agent 原子写入 /etc/ipsecvpn/secrets（不落库明文）:\n' + JSON.stringify(res, null, 2)
    await loadProfiles()
  } catch (e: any) {
    errMsg.value = e.message
  }
}

onMounted(loadProfiles)
</script>

<template>
  <div>
    <h2 style="margin: 0 0 14px;">赛事拓扑与站点配置（强 Schema 校验 + Dry-Run 差异生效）</h2>
    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>

    <div class="grid-2">
      <div class="card">
        <div class="row" style="margin-bottom: 10px;">
          <h3 style="margin: 0;">已保存赛事 Profile</h3>
          <div class="spacer"></div>
          <select v-model="hubRole" class="select" style="width: 170px;">
            <option value="primary">本 Hub 角色：主 Hub</option>
            <option value="backup">本 Hub 角色：备 Hub (#12)</option>
          </select>
        </div>
        <div class="row" style="margin-bottom: 12px;">
          <button
            v-for="p in profiles"
            :key="p.id"
            class="btn"
            :class="selectedId === p.id ? '' : 'btn-secondary'"
            @click="selectProfile(p)"
          >
            {{ p.id }} {{ p.active ? '★' : '' }}
          </button>
        </div>

        <div class="field">
          <label>赛事 Profile YAML（严格 Draft 2020-12 Schema，禁止重复键与 alias）</label>
          <textarea v-model="yamlText" class="textarea" rows="16" placeholder="粘贴或编辑 V2/V3/V4 赛事 YAML 配置..."></textarea>
        </div>
        <div class="row" style="margin-bottom: 10px;">
          <input v-model="note" class="input" style="flex: 1;" placeholder="变更说明（写入审计与版本历史）" />
        </div>
        <div class="row">
          <button class="btn btn-secondary" @click="validateYAML">1. 校验 Schema & 拓扑</button>
          <button class="btn" @click="saveProfile(true)">2. 保存并激活草稿</button>
          <button class="btn btn-secondary" @click="renderPreview">3. 预览 swanctl / nft</button>
          <button class="btn btn-secondary" @click="applyProfile(false)">4. Dry-Run Diff</button>
          <button class="btn btn-ok" @click="applyProfile(true)">5. 确认生效 Apply</button>
        </div>
      </div>

      <div>
        <div class="card">
          <h3>校验 / 渲染 / Dry-Run 输出</h3>
          <div class="code-block">{{ output || '点击左侧按钮校验或渲染配置预览。' }}</div>
        </div>

        <div class="card">
          <h3>PSK 密钥安全下发（只写不回显 · 不入库）</h3>
          <div class="grid-2">
            <div class="field">
              <label>站点 ID</label>
              <input v-model="secretSite" class="input" placeholder="ob-venue-1" />
            </div>
            <div class="field">
              <label>Secret Ref 路径</label>
              <input v-model="secretRef" class="input" />
            </div>
          </div>
          <div class="field">
            <label>64 位随机十六进制 PSK</label>
            <div class="row">
              <input v-model="secretPSK" class="input" style="flex: 1;" type="password" placeholder="点击右侧生成高强度随机 PSK" />
              <button class="btn btn-secondary" @click="randomHex64">随机生成</button>
              <button class="btn" @click="saveSecret">安全写入 root</button>
            </div>
          </div>
          <div v-if="secretsMeta.length" class="muted" style="margin-top: 8px;">
            已登记密钥摘要：{{ secretsMeta.map((s) => `${s.site_id}(${s.sha256.slice(0, 8)})`).join(', ') }}
          </div>
        </div>

        <div class="card">
          <h3>版本历史（可追溯回滚）</h3>
          <table v-if="revisions.length" class="table">
            <thead>
              <tr><th>时间</th><th>操作人</th><th>SHA256</th><th>备注</th></tr>
            </thead>
            <tbody>
              <tr v-for="r in revisions" :key="r.id">
                <td>{{ fmtDateTime(r.created_at) }}</td>
                <td>{{ r.operator }}</td>
                <td><code>{{ r.sha256.slice(0, 12) }}</code></td>
                <td>{{ r.note }}</td>
              </tr>
            </tbody>
          </table>
          <div v-else class="muted">暂无历史版本。</div>
        </div>
      </div>
    </div>
  </div>
</template>
