export interface ApiError extends Error {
  status?: number
}

export async function api<T = any>(url: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> | undefined)
  }
  const resp = await fetch(url, {
    credentials: 'include',
    ...options,
    headers
  })
  const text = await resp.text()
  let data: any = {}
  try {
    data = text ? JSON.parse(text) : {}
  } catch {
    data = { raw: text }
  }
  if (!resp.ok) {
    const err = new Error(data.error || data.detail || `HTTP ${resp.status}`) as ApiError
    err.status = resp.status
    throw err
  }
  return data as T
}

export interface MetricSample {
  id?: number
  ts_ms: number
  event_id: string
  hub_id: string
  site_id: string
  link_id: string
  isp_label: string
  l1_outer_state: number
  l1_outer_rtt_ms: number
  l1_outer_loss: number
  l1_mode: string
  l2_ike_state: number
  l2_child_state: number
  l2_rekeys_10m: number
  l3_rx_bps: number
  l3_tx_bps: number
  l3_rx_bytes: number
  l3_tx_bytes: number
  l3_xfrm_err_delta: number
  l3_nft_drop_delta: number
  l4_udp_state: number
  l4_udp_rtt_ms: number
  l4_udp_p95_ms: number
  l4_udp_loss: number
  root_cause: string
  root_detail: string
}

export interface TimelineEvent {
  id?: number
  ts_ms: number
  layer: string
  category: string
  severity: string
  site_id: string
  link_id: string
  source: string
  title: string
  detail_json: string
  root_cause: string
}

export interface DiagnosisResult {
  code: string
  severity: string
  summary_zh: string
  summary_en: string
  evidence: string[]
  layer_fault: string
}

export interface SyncedTimelineResponse {
  site_id: string
  from_ms: number
  to_ms: number
  samples: MetricSample[]
  events: TimelineEvent[]
  diagnosis: DiagnosisResult
}

export function fmtTime(tsMs: number): string {
  const d = new Date(tsMs)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

export function fmtDateTime(tsMs: number): string {
  if (!tsMs) return '-'
  const d = new Date(tsMs)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

export function downloadTextFile(filename: string, content: string) {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}
