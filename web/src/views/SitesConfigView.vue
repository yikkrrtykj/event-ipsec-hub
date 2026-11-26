<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, fmtDateTime } from '../api'
import { lang, t } from '../i18n'

const emit = defineEmits<{ (e: 'navigate', tab: string, site?: string): void }>()

type IkeIdType = 'address' | 'fqdn' | 'user_fqdn'

interface SiteForm {
  id: string
  display_name: string
  role: string
  country: string
  location_label: string
  public_endpoint: string
  ike_id_type: IkeIdType
  ike_id_value: string
  lan_cidrs_text: string
  vendor: string
  model: string
  os_version: string
  if_id: number
  secret_ref: string
  selector_mode: string
  route_priority: number
  outer_interface: string
  isp_label: string
  expanded: boolean
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

const form = ref({
  event_id: 'esports-event-2026',
  event_name: 'Multi-Venue Event Hub',
  event_purpose: '',
  hub_id: 'hub-vps-primary',
  hub_public_ip: '198.51.100.10',
  hub_ike_type: 'address' as IkeIdType,
  hub_ike_value: '',
  hub_provider: 'VPS-Primary',
  hub_location: 'Hong-Kong',
  hub_country: 'CN-HK',
  ike_enc: 'aes256',
  ike_hash: 'sha256',
  ike_dh: 'modp2048',
  esp_enc: 'aes256',
  esp_hash: 'sha256',
  esp_dh: 'modp2048',
  dpd_delay: 30,
  start_action: 'start',
  dpd_action: 'restart',
  close_action: 'start',
  ike_lifetime: 86400,
  child_lifetime: 14400
})

const sites = ref<SiteForm[]>([])
const pairs = ref<PairForm[]>([])

const secretSite = ref('')
const secretRef = ref('file:/etc/ipsecvpn/secrets/ob-venue-1.psk')
const secretPSK = ref('')

const siteIDs = computed(() => sites.value.map((s) => s.id).filter(Boolean))
const espIsGCM = computed(() => form.value.esp_enc.endsWith('gcm16'))

const ipv4RE = /^(\d{1,3}\.){3}\d{1,3}$/

function parseIdentityField(raw: string | undefined, fallbackIP: string): { type: IkeIdType; value: string } {
  const s = (raw || '').trim()
  if (!s) return { type: 'address', value: '' }
  if (s.startsWith('@')) return { type: 'fqdn', value: s.slice(1) }
  if (s.includes('@')) return { type: 'user_fqdn', value: s }
  if (ipv4RE.test(s)) {
    return { type: 'address', value: s === fallbackIP ? '' : s }
  }
  return { type: 'fqdn', value: s }
}

function formatIdentityValue(type: IkeIdType, value: string, fallbackIP: string): string {
  const v = (value || '').trim()
  if (type === 'fqdn') {
    if (!v) return fallbackIP
    return v.startsWith('@') ? v : `@${v}`
  }
  if (type === 'user_fqdn') {
    return v || fallbackIP
  }
  return v || fallbackIP
}

function buildProposals() {
  const f = form.value
  const ikeProp = f.ike_enc.endsWith('gcm16')
    ? `${f.ike_enc}-prf${f.ike_hash}-${f.ike_dh}`
    : `${f.ike_enc}-${f.ike_hash}-prf${f.ike_hash}-${f.ike_dh}`
  const espProp = f.esp_enc.endsWith('gcm16')
    ? `${f.esp_enc}-${f.esp_dh}`
    : `${f.esp_enc}-${f.esp_hash}-${f.esp_dh}`
  return { ikeProp, espProp }
}

function parseProposalIntoForm(ikeProp?: string, espProp?: string) {
  if (ikeProp) {
    const parts = ikeProp.split('-')
    if (parts.length >= 3) {
      form.value.ike_enc = parts[0]
      form.value.ike_dh = parts[parts.length - 1]
      const prf = parts.find((p) => p.startsWith('prfsha'))
      if (prf) form.value.ike_hash = prf.replace(/^prf/, '')
    }
  }
  if (espProp) {
    const parts = espProp.split('-')
    if (parts.length >= 2) {
      form.value.esp_enc = parts[0]
      form.value.esp_dh = parts[parts.length - 1]
      const hash = parts.find((p) => p.startsWith('sha'))
      if (hash) form.value.esp_hash = hash
    }
  }
}

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
  const { ikeProp, espProp } = buildProposals()
  const lines: string[] = [
    'schema_version: "2.0"',
    'event:',
    `  id: ${q(f.event_id)}`,
    `  name: ${q(f.event_name)}`
  ]
  if (f.event_purpose.trim()) {
    lines.push(`  purpose: ${q(f.event_purpose)}`)
  }
  const hubIke = formatIdentityValue(f.hub_ike_type, f.hub_ike_value, f.hub_public_ip)
  lines.push(
    '',
    'hub:',
    `  id: ${q(f.hub_id)}`,
    '  platform: ubuntu-24.04',
    `  public_endpoint: ${q(f.hub_public_ip)}`
  )
  if (hubIke && hubIke !== f.hub_public_ip.trim()) {
    lines.push(`  ike_identity: ${q(hubIke)}`)
  }
  lines.push(
    `  provider_label: ${q(f.hub_provider || 'VPS')}`,
    `  location_label: ${q(f.hub_location || 'Primary')}`
  )
  if (f.hub_country.trim()) lines.push(`  country: ${q(f.hub_country)}`)

  lines.push('', 'sites:')
  for (const s of sites.value) {
    const peerIke = formatIdentityValue(s.ike_id_type, s.ike_id_value, s.public_endpoint)
    lines.push(
      `  - id: ${q(s.id)}`,
      `    display_name: ${q(s.display_name || s.id)}`
    )
    if (s.role) lines.push(`    role: ${q(s.role)}`)
    if (s.country.trim()) lines.push(`    country: ${q(s.country)}`)
    if (s.location_label.trim()) lines.push(`    location_label: ${q(s.location_label)}`)
    lines.push(
      `    public_endpoint: ${q(s.public_endpoint)}`,
      `    ike_identity: ${q(peerIke)}`,
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
    `  ike_proposal: ${q(ikeProp)}`,
    `  esp_proposal: ${q(espProp)}`,
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
  const hubIke = parseIdentityField(p.hub?.ike_identity, p.hub?.public_endpoint || '')
  form.value = {
    event_id: p.event?.id || '',
    event_name: p.event?.name || '',
    event_purpose: p.event?.purpose || '',
    hub_id: p.hub?.id || 'hub-vps-primary',
    hub_public_ip: p.hub?.public_endpoint || '',
    hub_ike_type: hubIke.type,
    hub_ike_value: hubIke.value,
    hub_provider: p.hub?.provider_label || 'VPS',
    hub_location: p.hub?.location_label || '',
    hub_country: p.hub?.country || '',
    ike_enc: 'aes256',
    ike_hash: 'sha256',
    ike_dh: 'modp2048',
    esp_enc: 'aes256',
    esp_hash: 'sha256',
    esp_dh: 'modp2048',
    dpd_delay: p.security?.dpd_delay_seconds ?? 30,
    start_action: p.security?.start_action || 'start',
    dpd_action: p.security?.dpd_action || 'restart',
    close_action: p.security?.close_action || 'start',
    ike_lifetime: p.security?.ike_lifetime_seconds ?? 86400,
    child_lifetime: p.security?.child_lifetime_seconds ?? 14400
  }
  parseProposalIntoForm(p.security?.ike_proposal, p.security?.esp_proposal)

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
    const peerIke = parseIdentityField(st.ike_identity, st.public_endpoint || '')
    return {
      id: st.id || `site-${idx + 1}`,
      display_name: st.display_name || '',
      role: st.role || 'ob',
      country: st.country || '',
      location_label: st.location_label || '',
      public_endpoint: st.public_endpoint || '',
      ike_id_type: peerIke.type,
      ike_id_value: peerIke.value,
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
      expanded: idx === 0,
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
  const isEn = lang.value === 'en'
  form.value = {
    event_id: 'esports-multi-ob-hillstone',
    event_name: isEn ? 'Multi-OB Event Hub (Route-Based)' : '多场馆赛事互联（路由型）',
    event_purpose: isEn
      ? 'Connect isolated OB studios to central match servers via self-hosted VPN gateway'
      : '多演播室经自建 VPN 网关接入比赛服务器，演播室之间默认隔离',
    hub_id: 'hub-vps-primary',
    hub_public_ip: '198.51.100.10',
    hub_ike_type: 'address',
    hub_ike_value: '',
    hub_provider: 'VPS-Primary',
    hub_location: 'Hong-Kong',
    hub_country: 'CN-HK',
    ike_enc: 'aes256',
    ike_hash: 'sha256',
    ike_dh: 'modp2048',
    esp_enc: 'aes256',
    esp_hash: 'sha256',
    esp_dh: 'modp2048',
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
      display_name: isEn ? 'Match Server Room' : '比赛服务器机房',
      role: 'server',
      country: 'CN',
      location_label: 'Shanghai-IDC',
      public_endpoint: '203.0.113.10',
      ike_id_type: 'address',
      ike_id_value: '',
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
      expanded: true,
      show_advanced: false,
      source_ip: '',
      gateway: '',
      route_table: '',
      policy_priority: ''
    },
    {
      id: 'ob-venue-1',
      display_name: isEn ? 'OB Studio 1' : '演播室 OB-1',
      role: 'ob',
      country: 'CN',
      location_label: 'Beijing-Studio',
      public_endpoint: '203.0.113.21',
      ike_id_type: 'address',
      ike_id_value: '',
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
      expanded: false,
      show_advanced: false,
      source_ip: '',
      gateway: '',
      route_table: '',
      policy_priority: ''
    },
    {
      id: 'ob-venue-2',
      display_name: isEn ? 'OB Studio 2' : '演播室 OB-2',
      role: 'ob',
      country: 'JP',
      location_label: 'Tokyo-Studio',
      public_endpoint: '203.0.113.22',
      ike_id_type: 'address',
      ike_id_value: '',
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
      expanded: false,
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
  infoMsg.value = t('msgLoadedExample')
}

function setAllExpanded(val: boolean) {
  for (const s of sites.value) s.expanded = val
}

function selectorModeLabel(mode: string): string {
  if (mode === 'route_based') return t('modeRouteBased')
  if (mode === 'per_pair') return t('modePerPair')
  return t('modeExact')
}

function addSite() {
  const nextIdx = sites.value.length + 1
  const nextIfID = sites.value.reduce((mx, s) => Math.max(mx, Number(s.if_id) || 200), 200) + 1
  const id = `ob-venue-${nextIdx}`
  sites.value.push({
    id,
    display_name: lang.value === 'en' ? `Peer Site ${nextIdx}` : `对端站点 ${nextIdx}`,
    role: 'ob',
    country: 'CN',
    location_label: '',
    public_endpoint: `203.0.113.${20 + nextIdx}`,
    ike_id_type: 'address',
    ike_id_value: '',
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
    expanded: true,
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
      infoMsg.value = t('msgSyncedForm')
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
    infoMsg.value = t('msgValidated')
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
        note: note.value || 'Console update',
        activate
      })
    })
    selectedId.value = res.id
    output.value = JSON.stringify(res, null, 2)
    infoMsg.value = t('msgSaved', { id: res.id })
    note.value = ''
    await loadProfiles()
  } catch (e: any) {
    errMsg.value = e.message
  }
}

async function renderPreview() {
  if (!selectedId.value) {
    errMsg.value = t('msgNeedSavePreview')
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
    errMsg.value = t('msgNeedSaveApply')
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
    infoMsg.value = confirmed ? t('msgApplied') : t('msgDryRunDone')
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
    errMsg.value = t('msgNeedSavePsk')
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
    infoMsg.value = t('msgPskWritten', { site: secretSite.value })
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
      <h2 style="margin: 0; font-size: 18px;">{{ t('navConfig') }}</h2>
      <div class="spacer"></div>
      <div class="row">
        <button class="btn" :class="activeTab === 'visual' ? '' : 'btn-secondary'" @click="switchTab('visual')">{{ t('tabVisual') }}</button>
        <button class="btn" :class="activeTab === 'yaml' ? '' : 'btn-secondary'" @click="switchTab('yaml')">{{ t('tabYaml') }}</button>
        <button class="btn btn-secondary" @click="loadExampleTemplate">{{ t('loadExample') }}</button>
      </div>
    </div>

    <div v-if="errMsg" class="alert-banner alert-critical">{{ errMsg }}</div>
    <div v-if="infoMsg" class="alert-banner alert-ok">{{ infoMsg }}</div>

    <!-- Saved profile bar -->
    <div class="card" style="padding: 12px 16px;">
      <div class="row">
        <span class="muted" style="font-size: 13px;">{{ t('savedConfigs') }}</span>
        <button
          v-for="p in profiles"
          :key="p.id"
          class="btn"
          :class="selectedId === p.id ? '' : 'btn-secondary'"
          @click="selectProfile(p)"
        >
          {{ p.id }} <span v-if="p.active">· {{ t('currentTag') }}</span>
        </button>
        <span v-if="!profiles.length" class="muted">{{ t('noSavedConfigs') }}</span>
        <div class="spacer"></div>
        <select v-model="hubRole" class="select" style="width: 155px;">
          <option value="primary">{{ t('rolePrefixPrimary') }}</option>
          <option value="backup">{{ t('rolePrefixBackup') }}</option>
        </select>
      </div>
    </div>

    <!-- TAB 1: Visual Tunnel Configuration Wizard -->
    <div v-if="activeTab === 'visual'">
      <div class="card">
        <h3>{{ t('gatewayBasic') }}</h3>
        <div class="grid-3">
          <div class="field">
            <label>{{ t('cfgId') }}</label>
            <input v-model="form.event_id" class="input" placeholder="esports-2026" />
          </div>
          <div class="field">
            <label>{{ t('cfgName') }}</label>
            <input v-model="form.event_name" class="input" />
          </div>
          <div class="field">
            <label>{{ t('cfgPurpose') }}</label>
            <input v-model="form.event_purpose" class="input" :placeholder="t('cfgPurposePh')" />
          </div>
          <div class="field">
            <label>{{ t('hubId') }}</label>
            <input v-model="form.hub_id" class="input" />
          </div>
          <div class="field">
            <label>{{ t('hubPublicIp') }}</label>
            <input v-model="form.hub_public_ip" class="input" placeholder="198.51.100.10" />
          </div>
          <div class="field">
            <label>{{ t('hubIkeId') }}</label>
            <div class="input-combo">
              <select v-model="form.hub_ike_type" class="select">
                <option value="address">{{ t('ikeTypeAddress') }}</option>
                <option value="fqdn">{{ t('ikeTypeFqdn') }}</option>
                <option v-if="form.hub_ike_type === 'user_fqdn'" value="user_fqdn">{{ t('ikeTypeUserFqdn') }}</option>
              </select>
              <input
                v-model="form.hub_ike_value"
                class="input"
                :placeholder="form.hub_ike_type === 'address' ? t('hubIkeIdPh') : t('ikeFqdnPh')"
              />
            </div>
          </div>
          <div class="field">
            <label>{{ t('hubProvider') }}</label>
            <input v-model="form.hub_provider" class="input" placeholder="VPS-Primary" />
          </div>
          <div class="field">
            <label>{{ t('hubLocation') }}</label>
            <input v-model="form.hub_location" class="input" placeholder="Hong-Kong" />
          </div>
          <div class="field">
            <label>{{ t('hubCountry') }}</label>
            <input v-model="form.hub_country" class="input" placeholder="CN-HK" />
          </div>
        </div>
      </div>

      <div class="card">
        <div class="row" style="margin-bottom: 12px;">
          <h3 style="margin: 0;">{{ t('peerSitesTitle') }} ({{ sites.length }})</h3>
          <div class="spacer"></div>
          <button v-if="sites.length > 1" class="btn btn-secondary" @click="setAllExpanded(true)">{{ t('expandAll') }}</button>
          <button v-if="sites.length > 1" class="btn btn-secondary" @click="setAllExpanded(false)">{{ t('collapseAll') }}</button>
          <button class="btn" @click="addSite">{{ t('addSite') }}</button>
        </div>

        <div v-for="(s, idx) in sites" :key="idx" class="sub-card">
          <div class="row" :style="{ marginBottom: s.expanded ? '12px' : '0' }">
            <strong style="color: #f8fafc;">{{ t('tunnelIndex') }} #{{ idx + 1 }} · {{ s.id || t('unnamed') }}</strong>
            <span class="pill pill-info">if_id={{ s.if_id }}</span>
            <span class="muted">{{ s.public_endpoint }} · {{ s.lan_cidrs_text }} · {{ s.vendor }} · {{ selectorModeLabel(s.selector_mode) }}</span>
            <div class="spacer"></div>
            <button v-if="selectedId" class="btn btn-secondary" @click="emit('navigate', 'export', s.id)">{{ t('exportPeerBtn') }}</button>
            <button class="btn btn-secondary" @click="s.expanded = !s.expanded">
              {{ s.expanded ? t('collapse') : t('expand') }}
            </button>
            <button class="btn btn-danger" @click="removeSite(idx)">{{ t('deleteBtn') }}</button>
          </div>

          <template v-if="s.expanded">
            <div class="grid-3">
              <div class="field">
                <label>{{ t('siteId') }}</label>
                <input v-model="s.id" class="input" placeholder="ob-venue-1" />
              </div>
              <div class="field">
                <label>{{ t('siteName') }}</label>
                <input v-model="s.display_name" class="input" />
              </div>
              <div class="field">
                <label>{{ t('siteRole') }}</label>
                <select v-model="s.role" class="select">
                  <option value="server">{{ t('roleServer') }}</option>
                  <option value="ob">{{ t('roleOb') }}</option>
                  <option value="venue">{{ t('roleVenue') }}</option>
                  <option value="other">{{ t('roleOther') }}</option>
                </select>
              </div>
              <div class="field">
                <label>{{ t('peerPublicIp') }}</label>
                <input v-model="s.public_endpoint" class="input" placeholder="203.0.113.21" />
              </div>
              <div class="field">
                <label>{{ t('peerIkeId') }}</label>
                <div class="input-combo">
                  <select v-model="s.ike_id_type" class="select">
                    <option value="address">{{ t('ikeTypeAddress') }}</option>
                    <option value="fqdn">{{ t('ikeTypeFqdn') }}</option>
                    <option v-if="s.ike_id_type === 'user_fqdn'" value="user_fqdn">{{ t('ikeTypeUserFqdn') }}</option>
                  </select>
                  <input
                    v-model="s.ike_id_value"
                    class="input"
                    :placeholder="s.ike_id_type === 'address' ? t('peerIkeIdPh') : t('peerIkeFqdnPh')"
                  />
                </div>
              </div>
              <div class="field">
                <label>{{ t('peerLanCidrs') }}</label>
                <input v-model="s.lan_cidrs_text" class="input" placeholder="10.101.10.0/24" />
              </div>
              <div class="field">
                <label>{{ t('peerVendor') }}</label>
                <select v-model="s.vendor" class="select">
                  <option value="Hillstone">{{ t('vendorHillstone') }}</option>
                  <option value="Huawei">{{ t('vendorHuawei') }}</option>
                  <option value="Fortinet">{{ t('vendorFortinet') }}</option>
                  <option value="Cisco">{{ t('vendorCisco') }}</option>
                  <option value="CloudVPN">{{ t('vendorCloud') }}</option>
                  <option value="Generic">{{ t('vendorGeneric') }}</option>
                </select>
              </div>
              <div class="field">
                <label>{{ t('selectorMode') }}</label>
                <select v-model="s.selector_mode" class="select">
                  <option value="route_based">{{ t('modeRouteBased') }}</option>
                  <option value="exact">{{ t('modeExact') }}</option>
                  <option value="per_pair">{{ t('modePerPair') }}</option>
                </select>
              </div>
              <div class="field">
                <label>{{ t('ifIdAndPrio') }}</label>
                <div class="grid-2-tight">
                  <input v-model.number="s.if_id" type="number" class="input" />
                  <input v-model.number="s.route_priority" type="number" class="input" />
                </div>
              </div>
              <div class="field">
                <label>{{ t('localWanIf') }}</label>
                <input v-model="s.outer_interface" class="input" placeholder="eth0" />
              </div>
              <div class="field">
                <label>{{ t('ispLabel') }}</label>
                <input v-model="s.isp_label" class="input" placeholder="BGP-ISP-A" />
              </div>
              <div class="field">
                <label>{{ t('secretPath') }}</label>
                <input v-model="s.secret_ref" class="input" />
              </div>
            </div>

            <div class="row" style="margin-top: 4px;">
              <button class="btn btn-secondary" @click="s.show_advanced = !s.show_advanced">
                {{ s.show_advanced ? t('dualIspHide') : t('dualIspShow') }}
              </button>
            </div>

            <div v-if="s.show_advanced" class="grid-3" style="margin-top: 10px; padding-top: 10px; border-top: 1px dashed var(--border);">
              <div class="field">
                <label>{{ t('localSourceIp') }}</label>
                <input v-model="s.source_ip" class="input" placeholder="198.51.100.10" />
              </div>
              <div class="field">
                <label>{{ t('egressGateway') }}</label>
                <input v-model="s.gateway" class="input" placeholder="198.51.100.1" />
              </div>
              <div class="field">
                <label>{{ t('routeTablePrio') }}</label>
                <div class="grid-2-tight">
                  <input v-model="s.route_table" class="input" placeholder="101" />
                  <input v-model="s.policy_priority" class="input" placeholder="1001" />
                </div>
              </div>
            </div>
          </template>
        </div>
      </div>

      <div class="grid-2">
        <div class="card">
          <div class="row" style="margin-bottom: 10px;">
            <h3 style="margin: 0;">{{ t('trafficPolicyTitle') }}</h3>
            <div class="spacer"></div>
            <button class="btn btn-secondary" @click="addPair">{{ t('addRule') }}</button>
          </div>
          <div class="muted" style="margin-bottom: 10px;">{{ t('trafficPolicyHint') }}</div>
          <div v-for="(pr, idx) in pairs" :key="idx" class="sub-card" style="padding: 10px; margin-bottom: 8px;">
            <div class="row" style="margin-bottom: 8px;">
              <select v-model="pr.a" class="select" style="flex: 1;">
                <option value="">{{ t('selectSrcSite') }}</option>
                <option v-for="id in siteIDs" :key="id" :value="id">{{ id }}</option>
              </select>
              <span class="muted">↔</span>
              <select v-model="pr.b" class="select" style="flex: 1;">
                <option value="">{{ t('selectDstSite') }}</option>
                <option v-for="id in siteIDs" :key="id" :value="id">{{ id }}</option>
              </select>
              <button class="btn btn-danger" @click="removePair(idx)">{{ t('deleteBtn') }}</button>
            </div>
            <div class="grid-2-tight">
              <input v-model="pr.a_cidrs_text" class="input" :placeholder="t('srcCidrsPh')" />
              <input v-model="pr.b_cidrs_text" class="input" :placeholder="t('dstCidrsPh')" />
            </div>
          </div>
        </div>

        <div class="card">
          <h3>{{ t('secParamsTitle') }}</h3>
          <div class="grid-3">
            <div class="field">
              <label>{{ t('ikeEncAlg') }}</label>
              <select v-model="form.ike_enc" class="select">
                <option value="aes256">AES-256-CBC</option>
                <option value="aes128">AES-128-CBC</option>
                <option value="aes256gcm16">AES-256-GCM</option>
                <option value="aes128gcm16">AES-128-GCM</option>
              </select>
            </div>
            <div class="field">
              <label>{{ t('ikeAuthAlg') }}</label>
              <select v-model="form.ike_hash" class="select">
                <option value="sha256">SHA-256</option>
                <option value="sha384">SHA-384</option>
                <option value="sha512">SHA-512</option>
              </select>
            </div>
            <div class="field">
              <label>{{ t('ikeDhGroup') }}</label>
              <select v-model="form.ike_dh" class="select">
                <option value="modp2048">GROUP14 (modp2048)</option>
                <option value="modp3072">GROUP15 (modp3072)</option>
                <option value="modp4096">GROUP16 (modp4096)</option>
                <option value="ecp256">GROUP19 (ecp256)</option>
                <option value="ecp384">GROUP20 (ecp384)</option>
              </select>
            </div>
            <div class="field">
              <label>{{ t('espEncAlg') }}</label>
              <select v-model="form.esp_enc" class="select">
                <option value="aes256">AES-256-CBC</option>
                <option value="aes128">AES-128-CBC</option>
                <option value="aes256gcm16">AES-256-GCM</option>
                <option value="aes128gcm16">AES-128-GCM</option>
              </select>
            </div>
            <div class="field">
              <label>{{ t('espAuthAlg') }}</label>
              <select v-if="!espIsGCM" v-model="form.esp_hash" class="select">
                <option value="sha256">SHA-256</option>
                <option value="sha384">SHA-384</option>
                <option value="sha512">SHA-512</option>
              </select>
              <input v-else class="input" :value="t('aeadBuiltin')" disabled />
            </div>
            <div class="field">
              <label>{{ t('espPfsGroup') }}</label>
              <select v-model="form.esp_dh" class="select">
                <option value="modp2048">GROUP14 (modp2048)</option>
                <option value="modp3072">GROUP15 (modp3072)</option>
                <option value="modp4096">GROUP16 (modp4096)</option>
                <option value="ecp256">GROUP19 (ecp256)</option>
                <option value="ecp384">GROUP20 (ecp384)</option>
              </select>
            </div>
          </div>

          <div class="grid-3" style="margin-top: 6px; padding-top: 10px; border-top: 1px solid var(--border);">
            <div class="field">
              <label>{{ t('ikeLifetime') }}</label>
              <input v-model.number="form.ike_lifetime" type="number" class="input" />
            </div>
            <div class="field">
              <label>{{ t('ipsecLifetime') }}</label>
              <input v-model.number="form.child_lifetime" type="number" class="input" />
            </div>
            <div class="field">
              <label>{{ t('dpdInterval') }}</label>
              <input v-model.number="form.dpd_delay" type="number" class="input" />
            </div>
            <div class="field">
              <label>{{ t('startAction') }}</label>
              <select v-model="form.start_action" class="select">
                <option value="start">{{ t('startActive') }}</option>
                <option value="trap">{{ t('startTrap') }}</option>
                <option value="none">{{ t('startNone') }}</option>
              </select>
            </div>
            <div class="field">
              <label>{{ t('dpdAction') }}</label>
              <select v-model="form.dpd_action" class="select">
                <option value="restart">{{ t('dpdRestart') }}</option>
                <option value="clear">{{ t('dpdClear') }}</option>
              </select>
            </div>
            <div class="field">
              <label>{{ t('closeAction') }}</label>
              <select v-model="form.close_action" class="select">
                <option value="start">{{ t('closeStart') }}</option>
                <option value="none">{{ t('closeNone') }}</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="row">
          <input v-model="note" class="input" style="flex: 1;" :placeholder="t('changeNotePh')" />
          <button class="btn btn-secondary" @click="validateYAML">{{ t('btnValidate') }}</button>
          <button class="btn" @click="saveProfile(true)">{{ t('btnSave') }}</button>
          <button class="btn btn-secondary" @click="renderPreview">{{ t('btnRender') }}</button>
          <button class="btn btn-secondary" @click="applyProfile(false)">{{ t('btnDryRun') }}</button>
          <button class="btn btn-ok" @click="applyProfile(true)">{{ t('btnApply') }}</button>
        </div>
      </div>
    </div>

    <!-- TAB 2: Raw YAML Editor -->
    <div v-if="activeTab === 'yaml'" class="card">
      <div class="row" style="margin-bottom: 10px;">
        <h3 style="margin: 0;">{{ t('yamlSourceTitle') }}</h3>
        <div class="spacer"></div>
        <button class="btn btn-secondary" @click="syncYAMLToForm">{{ t('syncToForm') }}</button>
      </div>
      <div class="field">
        <textarea v-model="yamlText" class="textarea" rows="18" :placeholder="t('yamlPh')"></textarea>
      </div>
      <div class="row" style="margin-bottom: 10px;">
        <input v-model="note" class="input" style="flex: 1;" :placeholder="t('changeNotePh')" />
      </div>
      <div class="row">
        <button class="btn btn-secondary" @click="validateYAML">{{ t('btnValidate') }}</button>
        <button class="btn" @click="saveProfile(true)">{{ t('btnSave') }}</button>
        <button class="btn btn-secondary" @click="renderPreview">{{ t('btnRender') }}</button>
        <button class="btn btn-secondary" @click="applyProfile(false)">{{ t('btnDryRun') }}</button>
        <button class="btn btn-ok" @click="applyProfile(true)">{{ t('btnApply') }}</button>
      </div>
    </div>

    <!-- Lower Panels: PSK Management, Output Preview, Revision History -->
    <div class="grid-2">
      <div class="card">
        <h3>{{ t('pskTitle') }}</h3>
        <div class="muted" style="margin-bottom: 10px;">{{ t('pskHint') }}</div>
        <div class="grid-2">
          <div class="field">
            <label>{{ t('colSite') }}</label>
            <select v-if="siteIDs.length" v-model="secretSite" class="select" @change="onSecretSiteChange">
              <option v-for="id in siteIDs" :key="id" :value="id">{{ id }}</option>
            </select>
            <input v-else v-model="secretSite" class="input" placeholder="ob-venue-1" />
          </div>
          <div class="field">
            <label>{{ t('secretPath') }}</label>
            <input v-model="secretRef" class="input" />
          </div>
        </div>
        <div class="field">
          <label>{{ t('pskHexLabel') }}</label>
          <div class="row">
            <input v-model="secretPSK" class="input" style="flex: 1;" type="password" :placeholder="t('pskHexPh')" />
            <button class="btn btn-secondary" @click="randomHex64">{{ t('btnRandomGen') }}</button>
            <button class="btn" @click="saveSecret">{{ t('btnWritePsk') }}</button>
          </div>
        </div>
        <div v-if="secretsMeta.length" class="muted" style="margin-top: 8px;">
          {{ t('configuredDigests') }}{{ secretsMeta.map((s) => `${s.site_id} (${s.sha256.slice(0, 8)})`).join(', ') }}
        </div>
      </div>

      <div class="card">
        <h3>{{ t('execOutput') }}</h3>
        <div class="code-block" style="max-height: 260px;">{{ output || t('noOutput') }}</div>
      </div>
    </div>

    <div class="card">
      <h3>{{ t('revHistory') }}</h3>
      <table v-if="revisions.length" class="table">
        <thead>
          <tr>
            <th>{{ t('colTime') }}</th>
            <th>{{ t('colOperator') }}</th>
            <th>{{ t('colDigest') }}</th>
            <th>{{ t('colNote') }}</th>
          </tr>
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
      <div v-else class="muted">{{ t('noHistory') }}</div>
    </div>
  </div>
</template>
