import { useState, useEffect, useRef, type Dispatch, type SetStateAction } from 'react'

function readStorage<T>(key: string, defaultValue: T): T {
  try {
    const stored = localStorage.getItem(key)
    return stored !== null ? (JSON.parse(stored) as T) : defaultValue
  } catch {
    return defaultValue
  }
}

export function useLocalStorage<T>(key: string, defaultValue: T): [T, Dispatch<SetStateAction<T>>] {
  const [value, setValue] = useState<T>(() => readStorage(key, defaultValue))

  // Always track the latest defaultValue so a key-change reset uses the
  // current default. Assigned during render (safe for refs) so it stays
  // current without adding defaultValue to any effect's dependency array —
  // callers may pass non-stable literals ([] / {}) that would cause spurious
  // effect re-runs if included in deps.
  const defaultRef = useRef(defaultValue)
  defaultRef.current = defaultValue

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
