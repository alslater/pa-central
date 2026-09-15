/**
 * api.ts's request() — the dispatch half of the auth:unauthorized race fix.
 *
 * useAuth's listener (useAuthSetToken.test.tsx) only clears auth when the
 * failed request's token matches what's currently in localStorage — but
 * that only works if the event actually carries the token the failed
 * request used. This pins the other half: the dispatched event's `detail`.
 */
import { vi, beforeEach, afterEach, describe, it, expect } from 'vitest'
import { api } from '@/lib/api'

describe('api.ts request() — auth:unauthorized event payload', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  afterEach(() => {
    localStorage.clear()
    vi.unstubAllGlobals()
  })

  it('carries the token the failed request actually authenticated with', async () => {
    localStorage.setItem('token', 'token-at-request-time')
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      status: 401,
      ok: false,
      json: async () => ({ detail: 'Unauthorized' }),
    }))

    let capturedDetail: { token: string | null } | undefined
    const listener = (event: Event) => {
      capturedDetail = (event as CustomEvent<{ token: string | null }>).detail
    }
    window.addEventListener('auth:unauthorized', listener)

    await expect(api.auth.me()).rejects.toThrow('Unauthorized')

    window.removeEventListener('auth:unauthorized', listener)
    expect(capturedDetail).toEqual({ token: 'token-at-request-time' })
  })

  it("carries the request's own token, not whatever localStorage holds by the time the 401 is processed", async () => {
    // The core of the race this fix closes: the token is read once, at
    // request-send time (api.ts's own `getToken()` call inside
    // request()) — captured in a local variable — not re-read from
    // localStorage after the fetch resolves. A concurrent setToken()
    // call between send and response must not change what this event
    // reports.
    localStorage.setItem('token', 'old-token')
    vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => {
      // Simulate a concurrent setToken() installing a replacement while
      // this request is still in flight.
      localStorage.setItem('token', 'new-token')
      return { status: 401, ok: false, json: async () => ({ detail: 'Unauthorized' }) }
    }))

    let capturedDetail: { token: string | null } | undefined
    const listener = (event: Event) => {
      capturedDetail = (event as CustomEvent<{ token: string | null }>).detail
    }
    window.addEventListener('auth:unauthorized', listener)

    await expect(api.auth.me()).rejects.toThrow('Unauthorized')

    window.removeEventListener('auth:unauthorized', listener)
    expect(capturedDetail).toEqual({ token: 'old-token' })
    expect(localStorage.getItem('token')).toBe('new-token')
  })
})
