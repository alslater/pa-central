import { useState, useEffect, useRef, useCallback, type Dispatch, type SetStateAction, type KeyboardEvent as ReactKeyboardEvent } from 'react'

function readStorage<T>(key: string, defaultValue: T): T {
  try {
    const stored = localStorage.getItem(key)
    return stored !== null ? (JSON.parse(stored) as T) : defaultValue
  } catch {
    return defaultValue
  }
}

/**
 * Manages roving tabIndex keyboard navigation for a WAI-ARIA tablist.
 * Returns a ref-callback to attach to each tab button and an onKeyDown handler
 * to attach to the same buttons. Arrow keys, Home, and End move selection and
 * shift DOM focus to the newly active tab.
 */
export function useRovingTabs<T extends string>(
  ids: readonly T[],
  current: T,
  setCurrent: (id: T) => void,
): {
  tabRef: (id: T) => (el: HTMLButtonElement | null) => void
  onKeyDown: (e: ReactKeyboardEvent) => void
} {
  const refs = useRef<Map<T, HTMLButtonElement>>(new Map())
  // Keep ids and setCurrent in refs so the callbacks are stable across renders.
  const idsRef = useRef(ids)
  idsRef.current = ids // eslint-disable-line react-hooks/refs
  const setCurrentRef = useRef(setCurrent)
  setCurrentRef.current = setCurrent // eslint-disable-line react-hooks/refs
  const currentRef = useRef(current)
  currentRef.current = current // eslint-disable-line react-hooks/refs

  const tabRef = useCallback((id: T) => (el: HTMLButtonElement | null) => {
    if (el) refs.current.set(id, el)
    else refs.current.delete(id)
  }, [])

  const onKeyDown = useCallback((e: ReactKeyboardEvent) => {
    const ids = idsRef.current
    if (!ids.length) return
    const cur = ids.indexOf(currentRef.current)
    if (cur === -1) return
    let next: T | null = null
    if (e.key === 'ArrowRight') next = ids[(cur + 1) % ids.length]
    else if (e.key === 'ArrowLeft') next = ids[(cur - 1 + ids.length) % ids.length]
    else if (e.key === 'Home') next = ids[0]
    else if (e.key === 'End') next = ids[ids.length - 1]
    if (next) {
      e.preventDefault()
      setCurrentRef.current(next)
      const focusNext = () => refs.current.get(next!)?.focus()
      ;(globalThis.requestAnimationFrame ?? ((cb: FrameRequestCallback) => cb(0)))(focusNext)
    }
  }, [])

  return { tabRef, onKeyDown }
}

export function useLocalStorage<T>(key: string, defaultValue: T): [T, Dispatch<SetStateAction<T>>] {
  const [value, setValue] = useState<T>(() => readStorage(key, defaultValue))

  // Always track the latest defaultValue so a key-change reset uses the
  // current default. Assigned during render (safe for refs) so it stays
  // current without adding defaultValue to any effect's dependency array —
  // callers may pass non-stable literals ([] / {}) that would cause spurious
  // effect re-runs if included in deps.
  const defaultRef = useRef(defaultValue)
  defaultRef.current = defaultValue // eslint-disable-line react-hooks/refs

  // Re-initialise when key changes. React guarantees this fires before the
  // persist effect below (declaration order within a render), so prevKey is
  // updated before persistence runs.
  const prevKey = useRef(key)
  useEffect(() => {
    if (prevKey.current !== key) {
      prevKey.current = key
      setValue(readStorage(key, defaultRef.current))
    }
  }, [key])

  // Persist value to storage, but skip the write on the key-change render:
  // the persist effect runs after the re-key effect (same flush, declaration
  // order), so prevKey.current has already been updated to `key`. We detect
  // the key-change render by comparing against a separate persistedKey ref
  // that trails one render behind prevKey on key transitions.
  const persistedKey = useRef(key)
  useEffect(() => {
    if (persistedKey.current !== key) {
      // Key just changed — value is still the old state; skip the write so
      // we don't clobber the new key's stored value. persistedKey catches up
      // so the next value change (with the new key) persists normally.
      persistedKey.current = key
      return
    }
    try {
      localStorage.setItem(key, JSON.stringify(value))
    } catch {
      // storage full or unavailable — ignore
    }
  }, [key, value])

  return [value, setValue]
}
