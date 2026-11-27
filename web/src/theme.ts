import { ref } from 'vue'

export type ThemeMode = 'light' | 'dark'

const STORAGE_KEY = 'ipsecvpn_theme'

function readInitialTheme(): ThemeMode {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved === 'light' || saved === 'dark') return saved
  } catch {
    // ignore storage errors
  }
  return 'light'
}

export const theme = ref<ThemeMode>(readInitialTheme())

export function applyTheme(mode: ThemeMode) {
  theme.value = mode
  document.documentElement.setAttribute('data-theme', mode)
  try {
    localStorage.setItem(STORAGE_KEY, mode)
  } catch {
    // ignore
  }
}

export function toggleTheme() {
  applyTheme(theme.value === 'light' ? 'dark' : 'light')
}

// Apply immediately on module load so first paint matches persisted theme.
applyTheme(theme.value)
