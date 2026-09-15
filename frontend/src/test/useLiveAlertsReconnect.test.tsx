/**
 * LiveAlertsProvider — reconnects the SSE stream when the token it
 * authenticated with is replaced.
 *
 * A self-service password change bumps the account's token_epoch and
 * replaces the caller's token (useAuth's setToken), but the previous
 * version of this hook read localStorage once in a mount-only effect, so
 * a replaced token was never observed — the stream kept using the old
 * one until the backend's periodic epoch recheck (SSE_EPOCH_RECHECK_INTERVAL_SECONDS,
 * alerts.py) closed it, after which nothing reopened it until Shell
 * happened to remount.
 */
import { renderHook } from '@testing-library/react'
import { vi, beforeEach, afterEach, describe, it, expect } from 'vitest'
import { ReactNode } from 'react'
import { LiveAlertsProvider, useLiveAlertsContext } from '@/hooks/useLiveAlerts'

// AuthProvider mock: LiveAlertsProvider now calls useAuth() itself rather
// than receiving `token` as a prop, so tests must supply a fake AuthProvider
// (or mock useAuth directly) instead of passing `token` via renderHook props.
vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({ token: mockToken, user: mockUser, loading: mockLoading }),
}))

let mockToken: string | null = 'old-token'
let mockUser: { id: number } | null = { id: 1 }
let mockLoading = false

function wrapper({ children }: { children: ReactNode }) {
  return <LiveAlertsProvider>{children}</LiveAlertsProvider>
}

function fakeStreamResponse(): Response {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      // Left open deliberately — this hook's while(true) read loop should
      // simply keep awaiting the next chunk, exactly like a real SSE
      // connection sitting idle between events. Never closed by the fake
      // itself; only the hook's own AbortController tears it down.
      void controller
    },
  })
  return new Response(body, { status: 200 })
}

describe('LiveAlertsProvider reconnect on token replacement', () => {
  let fetchMock: ReturnType<typeof vi.fn>
  let abortedSignals: AbortSignal[]

  beforeEach(() => {
    mockToken = 'old-token'
    mockUser = { id: 1 }
    mockLoading = false
    abortedSignals = []
    fetchMock = vi.fn((_url: string, init?: RequestInit) => {
      if (init?.signal) abortedSignals.push(init.signal)
      return Promise.resolve(fakeStreamResponse())
    })
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('opens a new connection carrying the replacement token', async () => {
    const { rerender } = renderHook(() => useLiveAlertsContext(), { wrapper })
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/alerts/stream', expect.objectContaining({
      headers: { Authorization: 'Bearer old-token' },
    }))
    mockToken = 'new-token'
    rerender()
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/alerts/stream', expect.objectContaining({
      headers: { Authorization: 'Bearer new-token' },
    }))
  })

  it('aborts the previous connection rather than leaving it open alongside the new one', async () => {
    const { rerender } = renderHook(() => useLiveAlertsContext(), { wrapper })
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    const firstSignal = abortedSignals[0]
    expect(firstSignal.aborted).toBe(false)
    mockToken = 'new-token'
    rerender()
    await vi.waitFor(() => expect(firstSignal.aborted).toBe(true))
  })

  it('does not reconnect when the token is unchanged across a re-render', async () => {
    const { rerender } = renderHook(() => useLiveAlertsContext(), { wrapper })
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    rerender()
    await new Promise(resolve => setTimeout(resolve, 10))
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})
