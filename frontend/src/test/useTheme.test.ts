import { renderHook, act } from '@testing-library/react'
import { useTheme, type ThemeMode } from '@/hooks/useTheme'

const STORAGE_KEY = 'pa-theme'

function hasDark() {
  return document.documentElement.classList.contains('dark')
}

beforeEach(() => {
  localStorage.clear()
  document.documentElement.classList.remove('dark')
})

describe('useTheme', () => {
  it('defaults to dark mode when localStorage is empty', () => {
    const { result } = renderHook(() => useTheme())
    expect(result.current.mode).toBe('dark')
    expect(hasDark()).toBe(true)
  })

  it('reads initial mode from localStorage', () => {
    localStorage.setItem(STORAGE_KEY, 'light')
    const { result } = renderHook(() => useTheme())
    expect(result.current.mode).toBe('light')
    expect(hasDark()).toBe(false)
  })

  it('persists mode changes to localStorage', () => {
    const { result } = renderHook(() => useTheme())
    act(() => result.current.setMode('light'))
    expect(localStorage.getItem(STORAGE_KEY)).toBe('light')
  })

  it('removes .dark class when mode is light', () => {
    document.documentElement.classList.add('dark')
    const { result } = renderHook(() => useTheme())
    act(() => result.current.setMode('light'))
    expect(hasDark()).toBe(false)
  })

  it('adds .dark class when mode is dark', () => {
    const { result } = renderHook(() => useTheme())
    act(() => result.current.setMode('light'))
    act(() => result.current.setMode('dark'))
    expect(hasDark()).toBe(true)
  })

  it('applies system preference (dark) when mode is system', () => {
    const { result } = renderHook(() => useTheme())
    act(() => result.current.setMode('system'))
    expect(result.current.mode).toBe('system')
  })

  it('cycles through all three modes without error', () => {
    const { result } = renderHook(() => useTheme())
    const modes: ThemeMode[] = ['dark', 'light', 'system']
    for (const m of modes) {
      act(() => result.current.setMode(m))
      expect(result.current.mode).toBe(m)
    }
  })
})
