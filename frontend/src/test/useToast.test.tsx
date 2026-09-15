import { renderHook, act } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { useToast } from '@/components/ui'

describe('useToast dismiss', () => {
  it('clears an active toast', () => {
    const { result } = renderHook(() => useToast())
    act(() => { result.current.show('hello') })
    expect(result.current.Toast).not.toBeNull()
    act(() => { result.current.dismiss() })
    expect(result.current.Toast).toBeNull()
  })

  it('is a no-op when no toast is showing', () => {
    const { result } = renderHook(() => useToast())
    expect(() => act(() => { result.current.dismiss() })).not.toThrow()
    expect(result.current.Toast).toBeNull()
  })
})
