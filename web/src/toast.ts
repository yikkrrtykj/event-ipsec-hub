import { ref } from 'vue'

export type ToastKind = 'success' | 'error' | 'info'

export interface ToastItem {
  id: number
  kind: ToastKind
  message: string
}

export const toasts = ref<ToastItem[]>([])
let seq = 1

function push(kind: ToastKind, message: string, durationMs = 3200) {
  if (!message) return
  const id = seq++
  toasts.value.push({ id, kind, message })
  if (toasts.value.length > 4) {
    toasts.value.shift()
  }
  if (durationMs > 0) {
    window.setTimeout(() => dismissToast(id), durationMs)
  }
}

export function dismissToast(id: number) {
  toasts.value = toasts.value.filter((t) => t.id !== id)
}

export const toast = {
  success: (msg: string) => push('success', msg, 3000),
  error: (msg: string) => push('error', msg, 5200),
  info: (msg: string) => push('info', msg, 3000)
}

export async function copyToClipboard(val: string): Promise<boolean> {
  if (!val) return false
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(val)
      return true
    }
    throw new Error('clipboard fallback')
  } catch {
    try {
      const ta = document.createElement('textarea')
      ta.value = val
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
      return true
    } catch {
      return false
    }
  }
}
