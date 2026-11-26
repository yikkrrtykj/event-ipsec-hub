<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, fmtDateTime } from '../api'

interface SiteForm {
  id: string
  display_name: string
  role: string
  country: string
  location_label: string
  public_endpoint: string
  ike_identity: string
  lan_cidrs_text: string
  vendor: string
  model: string
  os_version: string
  // Primary tunnel link fields
  if_id: number
  secret_ref: string
  selector_mode: string
  route_priority: number
  outer_interface: string
  isp_label: string
  show_advanced: boolean
  source_ip: string
  gateway: string
  route_table: string
  policy_priority: string
}

interface PairForm {
  a: string
  b: string
  a_cidrs_text: string
  b_cidrs_text: string
}

const activeTab = ref<'visual' | 'yaml'>('visual')
const profiles = ref<any[]>([])
const secretsMeta = ref<any[]>([])
const selectedId = ref('')
const yamlText = ref('')
const hubRole = ref('primary')
const note = ref('')
const output = ref('')
const errMsg = ref('')
const infoMsg = ref('')
const revisions = ref<any[]>([])

// Structured visual form state
const form = ref({
  event_id: 'esports-event-2026',
  event_name: '赛事多场馆互联',
  event_purpose: '多演播室通过自建 VPN 网关安全接入比赛服务器',
  hub_id: 'hub-vps-primary',
  hub_public_ip: '198.51.100.10',
  hub_ike_id: '@hub-vps-primary.example',
  hub_provider: 'VPS-Primary',
  hub_location: 'Hong-Kong',
  hub_country: 'CN-HK',
  dpd_delay: 30,
  start_action: 'start',
  dpd_action: 'restart',
  close_action: 'start',
  ike_lifetime: 86400,
  child_lifetime: 14400
})

const sites = ref<SiteForm[]>([])
const pairs = ref<PairForm[]>([])

// Write-only PSK rotation form
const secretSite = ref('')
const secretRef = ref('file:/etc/ipsecvpn/secrets/ob-venue-1.psk')
const secretPSK = ref('')

const siteIDs = computed(() => sites.value.map((s) => s.id).filter(Boolean))

function q(v: string): string {
  const s = (v ?? '').trim()
  if (!s) return '""'
  if (/^[A-Za-z0-9._/-]+$/.test(s) && !/^(true|false|yes|no|on|off|null|~)$/i.test(s)) {
    return s
  }
  return JSON.stringify(s)
}

function splitCIDRs(text: string): string[] {
  return (text || '')
    .split(/[\s,，]+/)
    .map((x) => x.trim())
    .filter(Boolean)
}

function buildYAMLFromForm(): string {
  const f = form.value
  const lines: string[] = [
    'schema_version: "2.0"',
    'event:',
    `  id: ${q(f.event_id)}`,
    `  name: ${q(f.event_name)}`
  ]
  if (f.event_purpose.trim()) {
    lines.push(`  purpose: ${q(f.event_purpose)}`)
  }
  lines.push(
    '',
    'hub:',
    `  id: ${q(f.hub_id)}`,
    '  platform: ubuntu-24.04',
    `  public_endpoint: ${q(f.hub_public_ip)}`
  )
  if (f.hub_ike_id.trim()) lines.push(`  ike_identity: ${q(f.hub_ike_id)}`)
  lines.push(
    `  provider_label: ${q(f.hub_provider || 'VPS')}`,
    `  location_label: ${q(f.hub_location || 'Primary')}`
  )
  if (f.hub_country.trim()) lines.push(`  country: ${q(f.hub_country)}`)

  lines.push('', 'sites:')
  for (const s of sites.value) {
    lines.push(
      `  - id: ${q(s.id)}`,
      `    display_name: ${q(s.display_name || s.id)}`
    )
    if (s.role) lines.push(`    role: ${q(s.role)}`)
    if (s.country.trim()) lines.push(`    country: ${q(s.country)}`)
    if (s.location_label.trim()) lines.push(`    location_label: ${q(s.location_label)}`)
    lines.push(
      `    public_endpoint: ${q(s.public_endpoint)}`,
      `    ike_identity: ${q(s.ike_identity || s.public_endpoint)}`,
      '    lan_cidrs:'
    )
    for (const c of splitCIDRs(s.lan_cidrs_text)) {
      lines.push(`      - ${q(c)}`)
    }
    lines.push('    firewall:', `      vendor: ${q(s.vendor || 'Hillstone')}`)
    if (s.model.trim()) lines.push(`      model: ${q(s.model)}`)
    if (s.os_version.trim()) lines.push(`      os_version: ${q(s.os_version)}`)
  }

  lines.push(
    '',
    'security:',
    `  ike_lifetime_seconds: ${Number(f.ike_lifetime) || 86400}`,
    `  child_lifetime_seconds: ${Number(f.child_lifetime) || 14400}`,
    `  dpd_delay_seconds: ${Number(f.dpd_delay) || 30}`,
    `  start_action: ${q(f.start_action || 'start')}`,
    `  dpd_action: ${q(f.dpd_action || 'restart')}`,
    `  close_action: ${q(f.close_action || 'start')}`
  )

  lines.push('', 'site_links:')
  for (const s of sites.value) {
    const refPath = s.secret_ref.trim() || `file:/etc/ipsecvpn/secrets/${s.id}.psk`
    lines.push(
      `  - site_id: ${q(s.id)}`,
      `    secret_ref: ${q(refPath)}`,
      `    if_id: ${Number(s.if_id) || 201}`,
      `    selector_mode: ${q(s.selector_mode || 'route_based')}`,
      `    route_priority: ${Number(s.route_priority) || 10}`,
      '    outer_path:',
      `      interface: ${q(s.outer_interface || 'eth0')}`,
      `      isp_label: ${q(s.isp_label || 'ISP-A')}`
    )
    if (s.source_ip.trim()) lines.push(`      source_ip: ${q(s.source_ip)}`)
    if (s.gateway.trim()) lines.push(`      gateway: ${q(s.gateway)}`)
    if (s.route_table.trim() && Number(s.route_table) > 0) {
      lines.push(`      route_table: ${Number(s.route_table)}`)
    }
    if (s.policy_priority.trim() && Number(s.policy_priority) > 0) {
      lines.push(`      policy_priority: ${Number(s.policy_priority)}`)
    }
  }

  lines.push('', 'traffic_policy:', '  allowed_site_pairs:')
  for (const pr of pairs.value) {
    if (!pr.a || !pr.b) continue
    lines.push(`    - a: ${q(pr.a)}`, `      b: ${q(pr.b)}`)
    const ac = splitCIDRs(pr.a_cidrs_text)
    if (ac.length) {
      lines.push('      a_cidrs:')
      for (const c of ac) lines.push(`        - ${q(c)}`)
    }
    const bc = splitCIDRs(pr.b_cidrs_text)
    if (bc.length) {
      lines.push('      b_cidrs:')
      for (const c of bc) lines.push(`        - ${q(c)}`)
    }
  }

  lines.push('', 'backup:', '  enabled: false', '')
  return lines.join('\n')
}

function hydrateFormFromProfile(p: any) {
  if (!p) return
  form.value = {
    event_id: p.event?.id || '',
    event_name: p.event?.name || '',
    event_purpose: p.event?.purpose || '',
    hub_id: p.hub?.id || 'hub-vps-primary',
    hub_public_ip: p.hub?.public_endpoint || '',
    hub_ike_id: p.hub?.ike_identity || '',
    hub_provider: p.hub?.provider_label || 'VPS',
    hub_location: p.hub?.location_label || '',
    hub_country: p.hub?.country || '',
    dpd_delay: p.security?.dpd_delay_seconds ?? 30,
    start_action: p.security?.start_action || 'start',
    dpd_action: p.security?.dpd_action || 'restart',
    close_action: p.security?.close_action || 'start',
    ike_lifetime: p.security?.ike_lifetime_seconds ?? 86400,
    child_lifetime: p.security?.child_lifetime_seconds ?? 14400
  }

  const linkBySite = new Map<string, any>()
  for (const sl of p.site_links || []) {
    if (!linkBySite.has(sl.site_id)) {
      linkBySite.set(sl.site_id, sl)
    }
  }

  sites.value = (p.sites || []).map((st: any, idx: number) => {
    const sl = linkBySite.get(st.id) || {}
    const op = sl.outer_path || {}
    const hasAdv = Boolean(op.source_ip || op.gateway || op.route_table || op.policy_priority)
    return {
      id: st.id || `site-${idx + 1}`,
      display_name: st.display_name || '',
      role: st.role || 'ob',
      country: st.country || '',
      location_label: st.location_label || '',
      public_endpoint: st.public_endpoint || '',
      ike_identity: st.ike_identity || '',
      lan_cidrs_text: (st.lan_cidrs || []).join(', '),
      vendor: st.firewall?.vendor || 'Hillstone',
      model: st.firewall?.model || '',
      os_version: st.firewall?.os_version || '',
      if_id: sl.if_id || 201 + idx,
      secret_ref: sl.secret_ref || `file:/etc/ipsecvpn/secrets/${st.id}.psk`,
      selector_mode: sl.selector_mode || 'route_based',
      route_priority: sl.route_priority ?? 10,
      outer_interface: op.interface || 'eth0',
      isp_label: op.isp_label || 'ISP-A',
      show_advanced: hasAdv,
      source_ip: op.source_ip || '',
      gateway: op.gateway || '',
      route_table: op.route_table ? String(op.route_table) : '',
      policy_priority: op.policy_priority ? String(op.policy_priority) : ''
    }
  })

  pairs.value = (p.traffic_policy?.allowed_site_pairs || []).map((pr: any) => ({
    a: pr.a || '',
    b: pr.b || '',
    a_cidrs_text: (pr.a_cidrs || []).join(', '),
    b_cidrs_text: (pr.b_cidrs || []).join(', ')
  }))

  if (sites.value.length && !secretSite.value) {
    secretSite.value = sites.value[0].id
    secretRef.value = sites.value[0].secret_ref
  }
}

function loadExampleTemplate() {
  selectedId.value = ''
  revisions.value = []
  form.value = {
    event_id: 'esports-multi-ob-hillstone',
    event_name: '多场馆赛事互联（山石路由型）',
    event_purpose: '多演播室经自建 VPN 网关接入比赛服务器，演播室之间默认隔离',
    hub_id: 'hub-vps-primary',
    hub_public_ip: '198.51.100.10',
    hub_ike_id: '@hub-vps-primary.example',
    hub_provider: 'VPS-Primary',
    hub_location: 'Hong-Kong',
    hub_country: 'CN-HK',
    dpd_delay: 30,
    start_action: 'start',
    dpd_action: 'restart',
    close_action: 'start',
    ike_lifetime: 86400,
    child_lifetime: 14400
  }
  sites.value = [
    {
      id: 'server-core',
      display_name: '比赛服务器机房',
      role: 'server',
      country: 'CN',
      location_label: 'Shanghai-IDC',
      public_endpoint: '203.0.113.10',
      ike_identity: '@server-core.example',
      lan_cidrs_text: '10.100.10.0/24, 10.100.20.0/24',
      vendor: 'Hillstone',
      model: 'SG-6000-E3960',
      os_version: 'StoneOS 5.5R10',
      if_id: 201,
      secret_ref: 'file:/etc/ipsecvpn/secrets/server-core.psk',
      selector_mode: 'route_based',
      route_priority: 10,
      outer_interface: 'eth0',
      isp_label: 'BGP-ISP-A',
      show_advanced: false,
      source_ip: '',
      gateway: '',
      route_table: '',
      policy_priority: ''
    },
    {
      id: 'ob-venue-1',
      display_name: '演播室 OB-1',
      role: 'ob',
      country: 'CN',
      location_label: 'Beijing-Studio',
      public_endpoint: '203.0.113.21',
      ike_identity: '@ob-venue-1.example',
      lan_cidrs_text: '10.101.10.0/24',
      vendor: 'Hillstone',
      model: 'SG-6000-E1700',
      os_version: 'StoneOS 5.5R10',
      if_id: 202,
      secret_ref: 'file:/etc/ipsecvpn/secrets/ob-venue-1.psk',
      selector_mode: 'route_based',
      route_priority: 10,
      outer_interface: 'eth0',
      isp_label: 'BGP-ISP-A',
      show_advanced: false,
      source_ip: '',
      gateway: '',
      route_table: '',
      policy_priority: ''
    },
    {
      id: 'ob-venue-2',
      display_name: '演播室 OB-2',
      role: 'ob',
      country: 'JP',
      location_label: 'Tokyo-Studio',
      public_endpoint: '203.0.113.22',
      ike_identity: '@ob-venue-2.example',
      lan_cidrs_text: '10.102.10.0/24',
      vendor: 'Hillstone',
      model: 'SG-6000-E1700',
      os_version: 'StoneOS 5.5R10',
      if_id: 203,
      secret_ref: 'file:/etc/ipsecvpn/secrets/ob-venue-2.psk',
      selector_mode: 'per_pair',
      route_priority: 10,
      outer_interface: 'eth0',
      isp_label: 'BGP-ISP-A',
      show_advanced: false,
      source_ip: '',
      gateway: '',
      route_table: '',
      policy_priority: ''
    }
  ]
  pairs.value = [
    { a: 'ob-venue-1', b: 'server-core', a_cidrs_text: '10.101.10.0/24', b_cidrs_text: '10.100.10.0/24, 10.100.20.0/24' },
    { a: 'ob-venue-2', b: 'server-core', a_cidrs_text: '10.102.10.0/24', b_cidrs_text: '10.100.10.0/24' }
  ]
  yamlText.value = buildYAMLFromForm()
  secretSite.value = 'ob-venue-1'
  secretRef.value = 'file:/etc/ipsecvpn/secrets/ob-venue-1.psk'
  infoMsg.value = '已载入多场馆示例配置，修改参数后可点击保存。'
}

function addSite() {
  const nextIdx = sites.value.length + 1
  const nextIfID = sites.value.reduce((mx, s) => Math.max(mx, Number(s.if_id) || 200), 200) + 1
  const id = `ob-venue-${nextIdx}`
  sites.value.push({
    id,
    display_name: `对端站点 ${nextIdx}`,
    role: 'ob',
    country: 'CN',
    location_label: '',
    public_endpoint: `203.0.113.${20 + nextIdx}`,
    ike_identity: `@${id}.example`,
    lan_cidrs_text: `10.${100 + nextIdx}.10.0/24`,
    vendor: 'Hillstone',
    model: '',
    os_version: '',
    if_id: nextIfID,
    secret_ref: `file:/etc/ipsecvpn/secrets/${id}.psk`,
    selector_mode: 'route_based',
    route_priority: 10,
    outer_interface: 'eth0',
    isp_label: 'ISP-A',
    show_advanced: false,
    source_ip: '',
    gateway: '',
    route_table: '',
    policy_priority: ''
  })
}

function removeSite(idx: number) {
  sites.value.splice(idx, 1)
}

function addPair() {
  const ids = siteIDs.value
  pairs.value.push({
    a: ids[1] || ids[0] || '',
    b: ids[0] || '',
    a_cidrs_text: '',
    b_cidrs_text: ''
  })
}

function removePair(idx: number) {
  pairs.value.splice(idx, 1)
}

function onSecretSiteChange() {
  const hit = sites.value.find((s) => s.id === secretSite.value)
  if (hit && hit.secret_ref) {
    secretRef.value = hit.secret_ref
  } else if (secretSite.value) {
    secretRef.value = `file:/etc/ipsecvpn/secrets/${secretSite.value}.psk`
  }
}

function switchTab(tab: 'visual' | 'yaml') {
  if (tab === 'yaml' && activeTab.value === 'visual' && sites.value.length > 0) {
    yamlText.value = buildYAMLFromForm()
  }
  activeTab.value = tab
}

async function syncYAMLToForm() {
  errMsg.value = ''
  infoMsg.value = ''
  try {
    const res = await api('/api/v1/profiles/validate', {
      method: 'POST',
      body: JSON.stringify({ yaml_content: yamlText.value })
    })
    if (res.profile) {
      hydrateFormFromProfile(res.profile)
      activeTab.value = 'visual'
      infoMsg.value = '已从 YAML 同步到可视化表单。'
    }
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function loadProfiles() {
  const res = await api('/api/v1/profiles')
  profiles.value = res.profiles || []
  secretsMeta.value = res.secrets_meta || []
  if (profiles.value.length) {
    const target = profiles.value.find((p) => p.id === selectedId.value) || profiles.value[0]
    await selectProfile(target)
  } else if (sites.value.length === 0) {
    loadExampleTemplate()
  }
}

async function selectProfile(p: any) {
  selectedId.value = p.id
  yamlText.value = p.yaml_content
  hubRole.value = p.hub_role || 'primary'
  const [revs, parsed] = await Promise.all([
    api(`/api/v1/profiles/${encodeURIComponent(p.id)}/revisions`),
    api('/api/v1/profiles/validate', {
      method: 'POST',
      body: JSON.stringify({ yaml_content: p.yaml_content })
    }).catch(() => null)
  ])
  revisions.value = revs.revisions || []
  if (parsed?.profile) {
    hydrateFormFromProfile(parsed.profile)
  }
}

function currentYAML(): string {
  if (activeTab.value === 'visual') {
    yamlText.value = buildYAMLFromForm()
  }
  return yamlText.value
}

async function validateYAML() {
  errMsg.value = ''
  infoMsg.value = ''
  try {
    const res = await api('/api/v1/profiles/validate', {
      method: 'POST',
      body: JSON.stringify({ yaml_content: currentYAML() })
    })
    output.value = JSON.stringify({ status: res.status, event: res.event, backup: res.backup }, null, 2)
    infoMsg.value = '配置校验通过。'
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function saveProfile(activate = true) {
  errMsg.value = ''
  infoMsg.value = ''
  try {
    const bodyYAML = currentYAML()
    const res = await api('/api/v1/profiles', {
      method: 'POST',
      body: JSON.stringify({
        yaml_content: bodyYAML,
        hub_role: hubRole.value,
        note: note.value || '控制台更新',
        activate
      })
    })
    selectedId.value = res.id
    output.value = JSON.stringify(res, null, 2)
    infoMsg.value = `配置 ${res.id} 已保存。`
    note.value = ''
    await loadProfiles()
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function renderPreview() {
  if (!selectedId.value) {
    errMsg.value = '请先保存配置后再预览生成结果。'
    return
  }
  errMsg.value = ''
  try {
    const res = await api(`/api/v1/profiles/${encodeURIComponent(selectedId.value)}/render`)
    output.value = `=== swanctl.conf ===\n${res.files['swanctl.conf'].preview}\n=== ipsecvpn.nft ===\n${res.files['ipsecvpn.nft'].preview}`
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function applyProfile(confirmed: boolean) {
  if (!selectedId.value) {
    errMsg.value = '请先保存配置后再执行预检或生效。'
    return
  }
  errMsg.value = ''
  infoMsg.value = ''
  try {
    const res = await api(`/api/v1/profiles/${encodeURIComponent(selectedId.value)}/apply`, {
      method: 'POST',
      body: JSON.stringify({ confirmed, maintenance: false })
    })
    output.value = JSON.stringify(res, null, 2)
    infoMsg.value = confirmed ? '配置已下发生效。' : '变更预检完成，未修改运行状态。'
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
  if (!selectedId.value) {
    errMsg.value = '请先保存配置后再写入密钥。'
    return
  }
  errMsg.value = ''
  infoMsg.value = ''
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
    output.value = JSON.stringify(res, null, 2)
    infoMsg.value = `站点 ${secretSite.value} 的预共享密钥已写入主机。`
    await loadProfiles()
  } catch (e: any) {
    errMsg.value = e.message
  }
}

onMounted(loadProfiles)
</script>

<template>
  <div>
    <div class="row" style="margin-bottom: 14px;">
      <h2 style="margin: 0; font-size: 18px;">VPN 通道</h2>
      <div class="spacer"></div>
      <div class="row">
        <button class="btn" :class="activeTab === 'visual' ? '' : 'btn-secondary'" @click="switchTab('visual')">可视化配置</button>
        <button class="btn" :class="activeTab === 'yaml' ? '' : 'btn-secondary'" @click="switchTab('yaml')">YAML 源码</button>
        <button class="btn btn-secondary" @click="loadExampleTemplate">载入示例配置</button>
      </div>
    </div>

    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>
    <div v-if="infoMsg" class="alert-banner alert-ok">{{ infoMsg }}</div>

    <!-- Saved profile bar -->
    <div class="card" style="padding: 12px 16px;">
      <div class="row">
        <span class="muted" style="font-size: 13px;">已保存配置：</span>
        <button
          v-for="p in profiles"
          :key="p.id"
          class="btn"
          :class="selectedId === p.id ? '' : 'btn-secondary'"
          @click="selectProfile(p)"
        >
          {{ p.id }} <span v-if="p.active">· 当前</span>
        </button>
        <span v-if="!profiles.length" class="muted">暂无已保存配置</span>
        <div class="spacer"></div>
        <select v-model="hubRole" class="select" style="width: 140px;">
          <option value="primary">角色：主网关</option>
          <option value="backup">角色：备网关</option>
        </select>
      </div>
    </div>

    <!-- TAB 1: Visual Tunnel Configuration Wizard -->
    <div v-if="activeTab === 'visual'">
      <div class="card">
        <h3>网关基本信息</h3>
        <div class="grid-3">
          <div class="field">
            <label>配置 ID</label>
            <input v-model="form.event_id" class="input" placeholder="如 esports-2026" />
          </div>
          <div class="field">
            <label>配置名称</label>
            <input v-model="form.event_name" class="input" placeholder="如 赛事主会场互联" />
          </div>
          <div class="field">
            <label>用途说明</label>
            <input v-model="form.event_purpose" class="input" placeholder="选填" />
          </div>
          <div class="field">
            <label>本端网关标识</label>
            <input v-model="form.hub_id" class="input" />
          </div>
          <div class="field">
            <label>本端公网 IP</label>
            <input v-model="form.hub_public_ip" class="input" placeholder="198.51.100.10" />
          </div>
          <div class="field">
            <label>本端 IKE 标识</label>
            <input v-model="form.hub_ike_id" class="input" placeholder="留空则使用本端公网 IP" />
          </div>
          <div class="field">
            <label>线路提供商</label>
            <input v-model="form.hub_provider" class="input" placeholder="如 VPS-Primary" />
          </div>
          <div class="field">
            <label>所在地域</label>
            <input v-model="form.hub_location" class="input" placeholder="如 Hong-Kong" />
          </div>
          <div class="field">
            <label>国家/地区码</label>
            <input v-model="form.hub_country" class="input" placeholder="如 CN-HK" />
          </div>
        </div>
      </div>

      <div class="card">
        <div class="row" style="margin-bottom: 12px;">
          <h3 style="margin: 0;">对端站点与隧道列表</h3>
          <div class="spacer"></div>
          <button class="btn btn-secondary" @click="addSite">+ 添加站点</button>
        </div>

        <div
          v-for="(s, idx) in sites"
          :key="idx"
          style="border: 1px solid var(--border); border-radius: 8px; padding: 14px; margin-bottom: 12px; background: #fbfcfe;"
        >
          <div class="row" style="margin-bottom: 10px;">
            <strong>通道 #{{ idx + 1 }} · {{ s.id || '未命名' }}</strong>
            <span class="pill pill-info">XFRM if_id={{ s.if_id }}</span>
            <div class="spacer"></div>
            <button class="btn btn-secondary" @click="s.show_advanced = !s.show_advanced">
              {{ s.show_advanced ? '收起双线路由' : '双线策略路由' }}
            </button>
            <button class="btn btn-danger" @click="removeSite(idx)">删除</button>
          </div>

          <div class="grid-3">
            <div class="field">
              <label>站点 ID</label>
              <input v-model="s.id" class="input" placeholder="ob-venue-1" />
            </div>
            <div class="field">
              <label>站点名称</label>
              <input v-model="s.display_name" class="input" placeholder="演播室 OB-1" />
            </div>
            <div class="field">
              <label>站点角色</label>
              <select v-model="s.role" class="select">
                <option value="server">业务服务器 (server)</option>
                <option value="ob">演播室 / OB (ob)</option>
                <option value="venue">赛场 (venue)</option>
                <option value="other">其他 (other)</option>
              </select>
            </div>
            <div class="field">
              <label>对端公网 IP</label>
              <input v-model="s.public_endpoint" class="input" placeholder="203.0.113.21" />
            </div>
            <div class="field">
              <label>对端 IKE 标识</label>
              <input v-model="s.ike_identity" class="input" placeholder="@ob-venue-1.example 或公网 IP" />
            </div>
            <div class="field">
              <label>对端内网网段（逗号分隔）</label>
              <input v-model="s.lan_cidrs_text" class="input" placeholder="10.101.10.0/24" />
            </div>
            <div class="field">
              <label>对端设备厂商</label>
              <select v-model="s.vendor" class="select">
                <option value="Hillstone">山石网科 (Hillstone)</option>
                <option value="Huawei">华为 (Huawei)</option>
                <option value="Fortinet">飞塔 (Fortinet)</option>
                <option value="Cisco">思科 (Cisco)</option>
                <option value="TencentCloud">腾讯云 VPN 网关</option>
                <option value="Generic">通用设备 (Generic)</option>
              </select>
            </div>
            <div class="field">
              <label>协商模式</label>
              <select v-model="s.selector_mode" class="select">
                <option value="route_based">路由型 (0.0.0.0/0)</option>
                <option value="exact">策略型 (精确网段)</option>
                <option value="per_pair">多子网拆分 (per_pair)</option>
              </select>
            </div>
            <div class="field">
              <label>XFRM 通道号 (if_id) / 路由优先级</label>
              <div class="row">
                <input v-model.number="s.if_id" type="number" class="input" style="width: 50%;" />
                <input v-model.number="s.route_priority" type="number" class="input" style="width: 50%;" />
              </div>
            </div>
            <div class="field">
              <label>本端出口网卡</label>
              <input v-model="s.outer_interface" class="input" placeholder="eth0" />
            </div>
            <div class="field">
              <label>运营商标识</label>
              <input v-model="s.isp_label" class="input" placeholder="BGP-ISP-A" />
            </div>
            <div class="field">
              <label>密钥文件路径</label>
              <input v-model="s.secret_ref" class="input" />
            </div>
          </div>

          <div v-if="s.show_advanced" class="grid-3" style="margin-top: 8px; padding-top: 10px; border-top: 1px dashed var(--border);">
            <div class="field">
              <label>本端源 IP（双线可选）</label>
              <input v-model="s.source_ip" class="input" placeholder="如 198.51.100.10" />
            </div>
            <div class="field">
              <label>出口下一跳网关</label>
              <input v-model="s.gateway" class="input" placeholder="如 198.51.100.1" />
            </div>
            <div class="field">
              <label>策略路由表号 / 优先级</label>
              <div class="row">
                <input v-model="s.route_table" class="input" placeholder="101" />
                <input v-model="s.policy_priority" class="input" placeholder="1001" />
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="grid-2">
        <div class="card">
          <div class="row" style="margin-bottom: 10px;">
            <h3 style="margin: 0;">站点互通策略</h3>
            <div class="spacer"></div>
            <button class="btn btn-secondary" @click="addPair">+ 添加互通规则</button>
          </div>
          <div class="muted" style="margin-bottom: 10px;">仅放行下列站点间流量，未配置站点默认隔离。</div>
          <div v-for="(pr, idx) in pairs" :key="idx" style="border: 1px solid var(--border); border-radius: 6px; padding: 10px; margin-bottom: 8px;">
            <div class="row" style="margin-bottom: 8px;">
              <select v-model="pr.a" class="select" style="flex: 1;">
                <option value="">选择源站点</option>
                <option v-for="id in siteIDs" :key="id" :value="id">{{ id }}</option>
              </select>
              <span class="muted">↔</span>
              <select v-model="pr.b" class="select" style="flex: 1;">
                <option value="">选择目标站点</option>
                <option v-for="id in siteIDs" :key="id" :value="id">{{ id }}</option>
              </select>
              <button class="btn btn-danger" @click="removePair(idx)">删除</button>
            </div>
            <div class="grid-2">
              <input v-model="pr.a_cidrs_text" class="input" placeholder="源端网段（留空放行全部）" />
              <input v-model="pr.b_cidrs_text" class="input" placeholder="目标网段（留空放行全部）" />
            </div>
          </div>
        </div>

        <div class="card">
          <h3>IKE / IPsec 安全参数</h3>
          <div class="muted" style="margin-bottom: 10px;">默认采用 IKEv2 + AES-256-GCM / SHA256 / DH14 强加密套件。</div>
          <div class="grid-2">
            <div class="field">
              <label>IKE SA 生存时间 (秒)</label>
              <input v-model.number="form.ike_lifetime" type="number" class="input" />
            </div>
            <div class="field">
              <label>IPsec SA 生存时间 (秒)</label>
              <input v-model.number="form.child_lifetime" type="number" class="input" />
            </div>
            <div class="field">
              <label>DPD 探测间隔 (秒)</label>
              <input v-model.number="form.dpd_delay" type="number" class="input" />
            </div>
            <div class="field">
              <label>启动策略</label>
              <select v-model="form.start_action" class="select">
                <option value="start">主动建立 (start)</option>
                <option value="trap">按需触发 (trap)</option>
                <option value="none">被动等待 (none)</option>
              </select>
            </div>
            <div class="field">
              <label>DPD 超时动作</label>
              <select v-model="form.dpd_action" class="select">
                <option value="restart">自动重连 (restart)</option>
                <option value="clear">清除会话 (clear)</option>
              </select>
            </div>
            <div class="field">
              <label>对端断线动作</label>
              <select v-model="form.close_action" class="select">
                <option value="start">自动重连 (start)</option>
                <option value="none">保持断开 (none)</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="row">
          <input v-model="note" class="input" style="flex: 1;" placeholder="变更备注（选填）" />
          <button class="btn btn-secondary" @click="validateYAML">校验配置</button>
          <button class="btn" @click="saveProfile(true)">保存配置</button>
          <button class="btn btn-secondary" @click="renderPreview">预览生成文件</button>
          <button class="btn btn-secondary" @click="applyProfile(false)">变更预检</button>
          <button class="btn btn-ok" @click="applyProfile(true)">应用生效</button>
        </div>
      </div>
    </div>

    <!-- TAB 2: Raw YAML Editor -->
    <div v-if="activeTab === 'yaml'" class="card">
      <div class="row" style="margin-bottom: 10px;">
        <h3 style="margin: 0;">YAML 配置源码</h3>
        <div class="spacer"></div>
        <button class="btn btn-secondary" @click="syncYAMLToForm">同步到可视化表单</button>
      </div>
      <div class="field">
        <textarea v-model="yamlText" class="textarea" rows="18" placeholder="在此粘贴或编辑 YAML 配置..."></textarea>
      </div>
      <div class="row" style="margin-bottom: 10px;">
        <input v-model="note" class="input" style="flex: 1;" placeholder="变更备注（选填）" />
      </div>
      <div class="row">
        <button class="btn btn-secondary" @click="validateYAML">校验配置</button>
        <button class="btn" @click="saveProfile(true)">保存配置</button>
        <button class="btn btn-secondary" @click="renderPreview">预览生成文件</button>
        <button class="btn btn-secondary" @click="applyProfile(false)">变更预检</button>
        <button class="btn btn-ok" @click="applyProfile(true)">应用生效</button>
      </div>
    </div>

    <!-- Lower Panels: PSK Management, Output Preview, Revision History -->
    <div class="grid-2">
      <div class="card">
        <h3>预共享密钥 (PSK)</h3>
        <div class="muted" style="margin-bottom: 10px;">密钥直接写入主机受保护目录，不存入数据库且不支持明文回显。</div>
        <div class="grid-2">
          <div class="field">
            <label>站点</label>
            <select v-if="siteIDs.length" v-model="secretSite" class="select" @change="onSecretSiteChange">
              <option v-for="id in siteIDs" :key="id" :value="id">{{ id }}</option>
            </select>
            <input v-else v-model="secretSite" class="input" placeholder="ob-venue-1" />
          </div>
          <div class="field">
            <label>密钥路径</label>
            <input v-model="secretRef" class="input" />
          </div>
        </div>
        <div class="field">
          <label>64 位十六进制密钥</label>
          <div class="row">
            <input v-model="secretPSK" class="input" style="flex: 1;" type="password" placeholder="点击右侧随机生成" />
            <button class="btn btn-secondary" @click="randomHex64">随机生成</button>
            <button class="btn" @click="saveSecret">写入密钥</button>
          </div>
        </div>
        <div v-if="secretsMeta.length" class="muted" style="margin-top: 8px;">
          已配置摘要：{{ secretsMeta.map((s) => `${s.site_id} (${s.sha256.slice(0, 8)})`).join('，') }}
        </div>
      </div>

      <div class="card">
        <h3>执行结果</h3>
        <div class="code-block" style="max-height: 260px;">{{ output || '暂无输出。' }}</div>
      </div>
    </div>

    <div class="card">
      <h3>历史版本</h3>
      <table v-if="revisions.length" class="table">
        <thead>
          <tr><th>时间</th><th>操作人</th><th>摘要</th><th>备注</th></tr>
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
      <div v-else class="muted">暂无历史记录。</div>
    </div>
  </div>
</template>
