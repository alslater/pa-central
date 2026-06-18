import { useEffect, useState } from 'react'

export type ThemeMode = 'dark' | 'light' | 'system'

const STORAGE_KEY = 'pa-theme'
const VALID_MODES = new Set<ThemeMode>(['dark', 'light', 'system'])

function parseMode(raw: string | null): ThemeMode {
  return raw !== null && VALID_MODES.has(raw as ThemeMode) ? (raw as ThemeMode) : 'dark'
}

function applyTheme(mode: ThemeMode) {
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
  const useDark = mode === 'dark' || (mode === 'system' && prefersDark)
  document.documentElement.classList.toggle('dark', useDark)
}

export function useTheme() {
  const [mode, setMode] = useState<ThemeMode>(
    () => parseMode(localStorage.getItem(STORAGE_KEY))
  )

  useEffect(() => {
    applyTheme(mode)
    localStorage.setItem(STORAGE_KEY, mode)
  }, [mode])

  // Re-apply when system preference changes (only matters in 'system' mode)
  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const handler = () => { if (mode === 'system') applyTheme('system') }
    if (mq.addEventListener) {
      mq.addEventListener('change', handler)
      return () => mq.removeEventListener('change', handler)
    } else {
      // Safari < 14 only supports the deprecated addListener/removeListener API
      mq.addListener(handler)
      return () => mq.removeListener(handler)
    }
  }, [mode])

  return { mode, setMode }
}
