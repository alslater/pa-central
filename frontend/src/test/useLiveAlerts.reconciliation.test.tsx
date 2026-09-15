import { renderHook, act } from '@testing-library/react'
import { vi, beforeEach, afterEach, describe, it, expect } from 'vitest'
import { ReactNode } from 'react'
import {
  LiveAlertsProvider, useLiveAlertsContext,
  sseReconnectBackoffMs, SSE_RECONNECT_MAX_BACKOFF_MS,
} from '@/hooks/useLiveAlerts'

function errorResponse(status: number) {
  // An HTTP error response resolves fetch() normally — it does not reject
  // — with a short body that reaches `done: true` on the very first
  // read(). A genuinely null body (`new Response(null, ...)`) makes
  // `res.body` itself null, which would throw inside `getReader()`
  // regardless of whether the status is checked — masking the exact bug
  // this test targets behind an unrelated crash. A real (non-empty)
  // ReadableStream body, with no further chunks ever pushed, is what
  // actually isolates the status check.
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode('error body'))
      controller.close()
    },
  })
  return Promise.resolve(new Response(body, { status }))
}

let mockToken: string | null = 'token'
let mockUser: { id: number } | null = { id: 1 }
let mockLoading = false

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({ token: mockToken, user: mockUser, loading: mockLoading }),
}))

function wrapper({ children }: { children: ReactNode }) {
  return <LiveAlertsProvider>{children}</LiveAlertsProvider>
}

function fakeStreamController() {
  let push: (chunk: string) => void = () => {}
  let close: () => void = () => {}
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      push = (chunk: string) => controller.enqueue(new TextEncoder().encode(chunk))
      close = () => controller.close()
    },
  })
  return { response: new Response(body, { status: 200 }), push: (c: string) => push(c), close: () => close() }
}

// Shared across every describe block below: each test may trigger a
// reconnect (token or identity change), and every fetch() call — initial
// or reconnect — must return a *fresh* stream so a later push() reaches
// the currently-open connection's reader, not an already-drained one.
let fetchMock: ReturnType<typeof vi.fn>
let pushEvent: (chunk: string) => void
let closeStream: () => void

beforeEach(() => {
  mockToken = 'token'; mockUser = { id: 1 }; mockLoading = false
  fetchMock = vi.fn(() => {
    const { response, push, close } = fakeStreamController()
    pushEvent = push
    closeStream = close
    return Promise.resolve(response)
  })
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => vi.unstubAllGlobals())

describe('LiveAlertsProvider arrival-order reconciliation', () => {
  it('response-first: registers, then the event arrives and dismisses the pending toast', async () => {
    const { result } = renderHook(() => useLiveAlertsContext(), { wrapper })
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled())
    // Registration is now rejected outright when its epoch doesn't match
    // the live session — read the real one rather than assuming 0 (the
    // identity-boundary effect bumps it once on initial mount).
    const epoch = result.current.getSessionEpoch()

    const dismiss = vi.fn()
    let stillPending: boolean | undefined
    act(() => {
      stillPending = result.current.registerPendingOp('op-1', { action: 'admin_reset', dismiss, epoch })
    })
    // No event had arrived yet — the op is genuinely still pending, so
    // callers (Users.tsx) know to show their own "sending…" toast.
    expect(stillPending).toBe(true)

    pushEvent(`data: ${JSON.stringify({
      type: 'admin_action_result', op_id: 'op-1', action: 'admin_reset',
      target_email: 'a@b.com', state: 'delivered_live',
    })}\n\n`)

    await vi.waitFor(() => expect(dismiss).toHaveBeenCalled())
  })

  it('event-first: an early event is claimed by a matching registerPendingOp with the same epoch', async () => {
    const { result } = renderHook(() => useLiveAlertsContext(), { wrapper })
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled())
    // The identity-boundary effect bumps the epoch once on initial mount
    // (prevUserId starts null, so the very first user.id is itself a
    // boundary crossing) — read the real value rather than assuming 0.
    // The event below is stored under this same connection's epoch.
    const epoch = result.current.getSessionEpoch()

    pushEvent(`data: ${JSON.stringify({
      type: 'admin_action_result', op_id: 'op-2', action: 'admin_reset',
      target_email: 'a@b.com', state: 'admission_refused',
    })}\n\n`)

    // Give the read loop a tick to process it into earlyResults.
    await new Promise(r => setTimeout(r, 10))

    const dismiss = vi.fn()
    let stillPending: boolean | undefined
    act(() => {
      stillPending = result.current.registerPendingOp('op-2', { action: 'admin_reset', dismiss, epoch })
    })
    // dismiss must NOT be called on the event-first path — nothing was
    // ever shown on the page's own toast to clear.
    expect(dismiss).not.toHaveBeenCalled()
    // The return value is the caller's only signal that the outcome was
    // already rendered here — callers (Users.tsx) rely on `false` to
    // suppress their own "sending…" toast for an op that's already done.
    expect(stillPending).toBe(false)
  })

  it('discardEarlyResult drops an early-arrived event without rendering it', async () => {
    // For an op_id whose HTTP response was itself the settled answer
    // (admission refused) — Users.tsx calls this instead of
    // registerPendingOp so the event doesn't linger in earlyResults until
    // some later, unrelated SSE message's opportunistic prune. Unlike
    // registerPendingOp's early-result branch, this must never call
    // renderOutcome: the caller already showed its own message from the
    // synchronous HTTP response, and a second toast for the same outcome
    // would be a confusing duplicate.
    const { result } = renderHook(() => useLiveAlertsContext(), { wrapper })
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled())
    const epoch = result.current.getSessionEpoch()

    pushEvent(`data: ${JSON.stringify({
      type: 'admin_action_result', op_id: 'op-discard', action: 'admin_reset',
      target_email: 'a@b.com', state: 'admission_refused',
    })}\n\n`)
    await new Promise(r => setTimeout(r, 10))

    act(() => { result.current.discardEarlyResult('op-discard') })

    // Proven indirectly: if the entry were still there, registerPendingOp
    // would find it, render its outcome, and return false (the event-first
    // path, proven by the test above). Registering the SAME op_id now
    // and getting `true` back proves the earlier entry is genuinely gone,
    // not merely inert.
    const dismiss = vi.fn()
    let stillPending: boolean | undefined
    act(() => {
      stillPending = result.current.registerPendingOp('op-discard', { action: 'admin_reset', dismiss, epoch })
    })
    expect(stillPending).toBe(true)
    expect(dismiss).not.toHaveBeenCalled()
  })

  it('discardEarlyResult is a harmless no-op when nothing is buffered for that op_id', async () => {
    const { result } = renderHook(() => useLiveAlertsContext(), { wrapper })
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled())

    expect(() => act(() => { result.current.discardEarlyResult('op-never-arrived') })).not.toThrow()
  })

  it('a registration whose epoch went stale mid-flight is rejected outright, before any map mutation or toast', async () => {
    // The regression this specifically guards: a wrong implementation
    // reading sessionEpoch.current *fresh inside registerPendingOp*
    // (rather than the value threaded through from before the caller's
    // own await) would compare the already-bumped epoch against itself —
    // a comparison that can never fail — and silently accept a stale
    // registration. This test controls the timing precisely: the epoch
    // is captured, THEN the session boundary fires, THEN registration is
    // attempted with the stale, pre-boundary value — mirroring exactly
    // how doResetPassword captures opEpoch before its own await, and a
    // logout can land while that await is still pending.
    const { result, rerender } = renderHook(() => useLiveAlertsContext(), { wrapper })
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled())

    const opEpoch = result.current.getSessionEpoch() // captured "before the await"

    mockUser = null // logout — the session boundary the in-flight request will race
    await act(async () => { rerender() })
    await vi.waitFor(() => expect(result.current.getSessionEpoch()).toBe(opEpoch + 1))

    const dismiss = vi.fn()
    let stillPending: boolean | undefined
    act(() => {
      // The response "resolves" here, after the boundary — registering
      // with the OLD opEpoch, not a freshly-read one.
      stillPending = result.current.registerPendingOp('op-3', { action: 'admin_reset', dismiss, epoch: opEpoch })
    })
    expect(stillPending).toBe(false)

    // Rejected before any mutation: a matching SSE event delivered
    // afterward must find no trace of this registration — not resolved,
    // not sitting in pendingOps waiting for an event that would then
    // wrongly show a toast under the new (logged-out-then-back-in) session.
    pushEvent(`data: ${JSON.stringify({
      type: 'admin_action_result', op_id: 'op-3', action: 'admin_reset',
      target_email: 'a@b.com', state: 'delivered_live',
    })}\n\n`)
    await new Promise(r => setTimeout(r, 20))
    expect(dismiss).not.toHaveBeenCalled()
  })
})

describe('LiveAlertsProvider identity boundary', () => {
  it('logout clears pendingOps/earlyResults/count and dismisses the active toast', async () => {
    const { result, rerender } = renderHook(() => useLiveAlertsContext(), { wrapper })
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled())

    const epochBefore = result.current.getSessionEpoch()
    const dismiss = vi.fn()
    act(() => {
      result.current.registerPendingOp('op-4', { action: 'admin_reset', dismiss, epoch: epochBefore })
    })

    mockUser = null // logout
    // The identity-boundary reset runs inside a useEffect, which commits
    // asynchronously relative to the render — a bare rerender() followed
    // immediately by a synchronous assertion races that effect under load
    // (confirmed intermittently failing in the full suite, though reliably
    // passing in isolation). Wrapping in an async act() flushes effects
    // before the assertion runs.
    await act(async () => {
      rerender()
    })

    // The identity boundary must have genuinely fired — not merely
    // "nothing crashed" — proven directly via getSessionEpoch() rather
    // than inferred from a side effect that another guard could also
    // produce. waitFor as a second line of defense in case the epoch
    // commit still lags the act() flush under heavier scheduling load.
    await vi.waitFor(() => expect(result.current.getSessionEpoch()).toBe(epochBefore + 1))

    // A subsequent event for op-4 (tagged with the OLD epoch) must not
    // resolve — pendingOps was cleared on the identity transition.
    pushEvent(`data: ${JSON.stringify({
      type: 'admin_action_result', op_id: 'op-4', action: 'admin_reset',
      target_email: 'a@b.com', state: 'delivered_live',
    })}\n\n`)
    await new Promise(r => setTimeout(r, 20))
    // Nothing resolved under the old epoch: the stored dismiss for op-4
    // is never invoked, and the unread-alert count stays at 0.
    expect(dismiss).not.toHaveBeenCalled()
    expect(result.current.count).toBe(0)
  })

  it('same-user token rotation (user.id unchanged) preserves pendingOps', async () => {
    const { result, rerender } = renderHook(() => useLiveAlertsContext(), { wrapper })
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled())
    const epoch = result.current.getSessionEpoch()

    const dismiss = vi.fn()
    act(() => {
      result.current.registerPendingOp('op-5', { action: 'admin_reset', dismiss, epoch })
    })

    mockToken = 'rotated-token' // same user.id, different token
    rerender()

    pushEvent(`data: ${JSON.stringify({
      type: 'admin_action_result', op_id: 'op-5', action: 'admin_reset',
      target_email: 'a@b.com', state: 'delivered_live',
    })}\n\n`)
    await vi.waitFor(() => expect(dismiss).toHaveBeenCalled())
  })
})

describe('LiveAlertsProvider malformed SSE payload resilience', () => {
  it('a malformed data: payload is dropped, not fatal — the connection keeps reading subsequent events', async () => {
    // Regression: JSON.parse used to run unguarded inside the read loop, so
    // a single malformed payload threw into the outer try/catch (which
    // treats ANY exception as "AbortError on unmount/reconnect, ignore"),
    // exiting the while(true) loop for good — permanently killing this
    // connection until a token/user change forces a reconnect. The
    // original pre-move implementation (Shell.tsx's useLiveAlerts)
    // wrapped exactly this per-line JSON.parse in its own try/catch and
    // kept reading; this proves that isolation is back.
    const { result } = renderHook(() => useLiveAlertsContext(), { wrapper })
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled())

    const dismiss = vi.fn()
    const epoch = result.current.getSessionEpoch()
    act(() => {
      result.current.registerPendingOp('op-after-malformed', { action: 'admin_reset', dismiss, epoch })
    })

    // Malformed JSON in the data: field.
    pushEvent('data: {not valid json\n\n')
    // A well-formed event for an unrelated op_id, to prove the read loop
    // is still alive and processing events after the malformed one.
    pushEvent(`data: ${JSON.stringify({
      type: 'admin_action_result', op_id: 'op-after-malformed', action: 'admin_reset',
      target_email: 'a@b.com', state: 'delivered_live',
    })}\n\n`)

    await vi.waitFor(() => expect(dismiss).toHaveBeenCalled())
  })
})

describe('sseReconnectBackoffMs', () => {
  it('doubles each attempt starting at 1s, capped at the max', () => {
    expect(sseReconnectBackoffMs(1)).toBe(1000)
    expect(sseReconnectBackoffMs(2)).toBe(2000)
    expect(sseReconnectBackoffMs(3)).toBe(4000)
    expect(sseReconnectBackoffMs(4)).toBe(8000)
    expect(sseReconnectBackoffMs(5)).toBe(16000)
    // 2^5 * 1000 = 32000, over the 30s cap.
    expect(sseReconnectBackoffMs(6)).toBe(SSE_RECONNECT_MAX_BACKOFF_MS)
    expect(sseReconnectBackoffMs(20)).toBe(SSE_RECONNECT_MAX_BACKOFF_MS)
  })
})

describe('LiveAlertsProvider transport-failure reconnect', () => {
  it('a genuine transport failure retries the connection under the same session, not permanently ending it', async () => {
    // Regression: the outer try/catch used to swallow every exception —
    // a real AbortError from unmount/reconnect (its intended purpose) AND
    // a genuine network failure alike — with no distinction and no retry.
    // Since nothing in [token, user?.id, loading] changes just because the
    // network blipped, a transient failure silently and permanently ended
    // live SSE delivery for the rest of the session. This proves the fix:
    // fetch rejecting with a plain network error (name !== 'AbortError')
    // is retried, and an event on the RETRIED connection still resolves a
    // pending op registered before the failure — proving state (pendingOps,
    // sessionEpoch) survived the reconnect rather than being reset.
    fetchMock.mockImplementationOnce(() => Promise.reject(new TypeError('Failed to fetch')))

    const { result } = renderHook(() => useLiveAlertsContext(), { wrapper })
    // First call is the one that's about to fail; wait for the retry's
    // own call before registering, so the op is in place when its event
    // arrives on the (second, successful) connection.
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))

    const dismiss = vi.fn()
    const epoch = result.current.getSessionEpoch()
    act(() => {
      result.current.registerPendingOp('op-after-reconnect', { action: 'admin_reset', dismiss, epoch })
    })

    // The retry's own backoff (1s for the first attempt) has to actually
    // elapse before the second fetch() fires — this is the one place in
    // this file that tolerates a real, short wait rather than a mocked
    // instant resolution, specifically to prove the delay is real.
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2), { timeout: 3000 })

    pushEvent(`data: ${JSON.stringify({
      type: 'admin_action_result', op_id: 'op-after-reconnect', action: 'admin_reset',
      target_email: 'a@b.com', state: 'delivered_live',
    })}\n\n`)
    await vi.waitFor(() => expect(dismiss).toHaveBeenCalled())
  }, 10000)

  it('does not retry when the failure is a genuine AbortError (unmount)', async () => {
    const { unmount } = renderHook(() => useLiveAlertsContext(), { wrapper })
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))

    unmount()
    // Give any (incorrect) retry a real window to fire — well under the
    // first backoff delay (1s), so a retry-on-abort bug would not yet
    // have had time to reconnect anyway, but this is checking it doesn't
    // even try: an unmounted provider has no controller.signal.aborted
    // check left to skip on, so a bug here would show up as a second
    // fetch() call scheduled regardless of the delay.
    await new Promise(r => setTimeout(r, 50))
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('a clean, server-initiated stream close still waits out one backoff step before reconnecting', async () => {
    // Regression this specifically guards, now the other direction from
    // its own original form: reader.read() returning { done: true } — a
    // normal EOF, e.g. a proxy or load balancer idle-closing the
    // connection, or the server recycling it — is not itself a failure,
    // but is NOT distinguishable from here from a broken proxy/server
    // that returns HTTP 200 with an immediately-closed or empty stream on
    // EVERY attempt: res.ok is true either way, so reader.read() just
    // returns {done: true} on the very first call and connectAndRead()
    // returns normally in both cases. Reconnecting with NO delay used to
    // mean that second, broken case became an unbounded, unthrottled
    // fetch loop — reproduced directly. This test now proves the fix:
    // even a genuinely clean close waits out sseReconnectBackoffMs(1)
    // before the next fetch(), bounding that loop, while an op registered
    // before the close still resolves on the reconnected stream — proving
    // session state survives the (now-delayed-but-still-automatic)
    // reconnect, same as before this fix.
    const { result } = renderHook(() => useLiveAlertsContext(), { wrapper })
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))

    const dismiss = vi.fn()
    const epoch = result.current.getSessionEpoch()
    act(() => {
      result.current.registerPendingOp('op-after-clean-close', { action: 'admin_reset', dismiss, epoch })
    })

    closeStream()
    // The reconnect must NOT happen near-instantly any more — a short
    // window is asserted to still be at 1 call, proving the backoff
    // step is real and not skipped for a clean close specifically.
    await new Promise(r => setTimeout(r, 100))
    expect(fetchMock).toHaveBeenCalledTimes(1)

    // The real backoff step (1s for the first attempt) does eventually
    // elapse and reconnect — this is the one place in this test (besides
    // the transport-failure test above) that tolerates a real, short wait
    // rather than a mocked instant resolution, specifically to prove the
    // delay is real.
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2), { timeout: 3000 })

    pushEvent(`data: ${JSON.stringify({
      type: 'admin_action_result', op_id: 'op-after-clean-close', action: 'admin_reset',
      target_email: 'a@b.com', state: 'delivered_live',
    })}\n\n`)
    await vi.waitFor(() => expect(dismiss).toHaveBeenCalled())
  }, 10000)

  it('does not escalate the backoff across repeated clean closes', async () => {
    // The other half of the fix this describes: EOF backoff resets
    // `attempt` back to 0 immediately, same as before this change — a run
    // of genuinely clean closes (a proxy recycling connections routinely,
    // say) must keep waiting the SAME first-step delay every time, not
    // climb toward the 30s ceiling the way a real failure streak does.
    // Only a broken server that returns EOF on literally every attempt
    // needs bounding at all, and the fix bounds it to "roughly one
    // request per backoff-floor interval," not an ever-growing gap.
    //
    // Real setTimeout is spied (not full fake timers, matching the
    // unbounded-retry test above) so each wait resolves on the next
    // microtask instead of after its real ~1s delay — three real backoff
    // steps would otherwise make this test unnecessarily slow, and the
    // point under test is which delay VALUE sseReconnectBackoffMs is
    // called with each time, not how long the wait actually takes.
    const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout')
      .mockImplementation((handler: TimerHandler) => {
        if (typeof handler === 'function') handler()
        return 0
      })

    renderHook(() => useLiveAlertsContext(), { wrapper })
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))

    closeStream()
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
    closeStream()
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3))
    closeStream()
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(4))

    // Every setTimeout call the reconnect loop made used the SAME delay
    // value — sseReconnectBackoffMs(1) — never an escalating one, proving
    // `attempt` never accumulated across the three clean closes above.
    const delaysUsed = setTimeoutSpy.mock.calls.map(call => call[1])
    expect(delaysUsed.every(d => d === sseReconnectBackoffMs(1))).toBe(true)
    expect(new Set(delaysUsed).size).toBe(1)

    setTimeoutSpy.mockRestore()
  })

  it('keeps retrying past 5 consecutive failures — an outage longer than the old ~31s budget does not permanently disable the connection', async () => {
    // Regression: an earlier version of this loop gave up after
    // SSE_RECONNECT_MAX_RETRIES (5) attempts (~31s of cumulative backoff),
    // returning from the retry loop for good. That reproduced the exact
    // bug this loop exists to fix, just with a longer fuse: any outage
    // longer than ~31s (a deploy, a brief infra blip) silently and
    // permanently disabled live delivery for the rest of an otherwise
    // valid session, recoverable only via a full page reload or a genuine
    // identity/token change. Retrying is now unbounded — only abort, an
    // auth failure, or an identity change end the loop.
    //
    // real setTimeout is spied (not full fake timers, which this suite
    // avoids elsewhere) so the exponential-then-30s-capped backoff still
    // runs through its own real arithmetic (sseReconnectBackoffMs is
    // called exactly as in production), but each wait resolves on the
    // next microtask instead of after the real multi-second delay — 6
    // consecutive real backoff steps (1+2+4+8+16+30s = 61s) would
    // otherwise make this test impractically slow.
    const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout')
      .mockImplementation((handler: TimerHandler) => {
        if (typeof handler === 'function') handler()
        return 0
      })

    const consecutiveFailures = 6 // one more than the old cutoff
    for (let i = 0; i < consecutiveFailures; i++) {
      fetchMock.mockImplementationOnce(() => Promise.reject(new TypeError('Failed to fetch')))
    }

    renderHook(() => useLiveAlertsContext(), { wrapper })
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))

    // A 7th call proves the loop survived all 6 failures above and is
    // still trying — the old cutoff would have stopped calling fetch()
    // again after the 6th attempt (5 retries following the 1st failure).
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(consecutiveFailures + 1))

    setTimeoutSpy.mockRestore()
  })
})

describe('LiveAlertsProvider HTTP-error response handling', () => {
  // Regression: fetch() resolves normally on an HTTP error response (401,
  // 502, 503...) — it only rejects on a network-level failure. Unchecked,
  // res.ok/res.status was never read, so a 401 or 502's short/empty body
  // reached `done: true` on the very first read() and was indistinguishable
  // from connectAndRead() returning after a genuine clean server close.
  // (Both now wait out the same first backoff step before reconnecting —
  // see the clean-close test above for why even a genuinely clean close
  // no longer reconnects instantly — so what actually distinguishes these
  // tests from that one is total attempt count: 401 stops outright with
  // no second attempt at all, and 502 keeps retrying past the first step.)
  // Before either fix existed, a stale/rotated token or a proxy returning
  // 502/503 under load produced an unbounded, unbacked-off busy loop of
  // fetch() calls.

  it('stops outright on a 401, without reconnecting', async () => {
    fetchMock.mockImplementationOnce(() => errorResponse(401))

    renderHook(() => useLiveAlertsContext(), { wrapper })
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))

    // Both a clean close and a retryable transport/HTTP failure now wait
    // out at least sseReconnectBackoffMs(1) (~1s) before reconnecting, so
    // the window here must clear that delay — a 401 that were merely
    // retried like either of those (instead of stopped outright) would
    // still show only one call yet, incorrectly appear to pass, within a
    // shorter window.
    await new Promise(r => setTimeout(r, 1500))
    expect(fetchMock).toHaveBeenCalledTimes(1)
  }, 10000)

  it('retries a 502 through the same capped backoff as a transport failure', async () => {
    fetchMock.mockImplementationOnce(() => errorResponse(502))

    const { result } = renderHook(() => useLiveAlertsContext(), { wrapper })
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))

    const dismiss = vi.fn()
    const epoch = result.current.getSessionEpoch()
    act(() => {
      result.current.registerPendingOp('op-after-502-retry', { action: 'admin_reset', dismiss, epoch })
    })

    // Real backoff delay, same as the transport-failure and clean-close
    // tests above — a 502 goes through the identical retry path as a
    // transport failure, not a special case of its own.
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2), { timeout: 3000 })

    pushEvent(`data: ${JSON.stringify({
      type: 'admin_action_result', op_id: 'op-after-502-retry', action: 'admin_reset',
      target_email: 'a@b.com', state: 'delivered_live',
    })}\n\n`)
    await vi.waitFor(() => expect(dismiss).toHaveBeenCalled())
  }, 10000)
})

describe('LiveAlertsProvider: epoch captured at true start, connection gated on resolved identity', () => {
  it('does not open a connection while loading is true (reload-with-stored-token)', async () => {
    mockLoading = true
    mockUser = null
    mockToken = 'stored-token'
    renderHook(() => useLiveAlertsContext(), { wrapper })
    await new Promise(r => setTimeout(r, 20))
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('opens the connection only once loading resolves to false and user is set', async () => {
    mockLoading = true
    mockUser = null
    mockToken = 'stored-token'
    const { rerender } = renderHook(() => useLiveAlertsContext(), { wrapper })
    await new Promise(r => setTimeout(r, 20))
    expect(fetchMock).not.toHaveBeenCalled()

    mockLoading = false
    mockUser = { id: 1 }
    rerender()
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
  })
})
