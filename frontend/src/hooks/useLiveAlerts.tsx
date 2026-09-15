import { createContext, useContext, useEffect, useRef, useState, ReactNode } from 'react'
import { useAuth } from '@/hooks/useAuth'
import { useToast } from '@/components/ui'

interface LiveAlertsCtx {
  count: number
  clear: () => void
  Toast: ReactNode | null
  registerPendingOp: (opId: string, entry: PendingOp) => boolean
  discardEarlyResult: (opId: string) => void
  getSessionEpoch: () => number
}

export interface PendingOp {
  action: 'admin_reset' | 'welcome_link'
  dismiss: () => void
  epoch: number
}

// Mirrors backend/app/schemas/__init__.py's AdminActionResultEvent
// discriminated union exactly (built by build_admin_action_result_event,
// never a raw dict) — six of the design spec's seven terminal states
// (`prep_failed` has no op_id and no SSE event at all; it's reported
// synchronously in the HTTP response instead). Tagged on `state` alone —
// no redundant `attempted`/`sent`/`still_live`/`account_deleted` fields:
// every one of those was fully determined by `state` already, on the
// backend, so carrying them here too would only be a second copy of the
// same fact that this file's own type guard would then have to check
// agrees with the first — state is authoritative, not merely convenient.
interface AdminActionResultEvent {
  type: 'admin_action_result'
  op_id: string
  action: 'admin_reset' | 'welcome_link'
  target_email: string
  state: 'admission_refused' | 'send_unconfirmed' | 'outcome_unknown'
    | 'delivered_live' | 'delivered_superseded' | 'delivered_account_gone'
}

const ADMIN_ACTION_RESULT_STATES = new Set([
  'admission_refused', 'send_unconfirmed', 'outcome_unknown',
  'delivered_live', 'delivered_superseded', 'delivered_account_gone',
])

// Parsed SSE JSON is untyped (JSON.parse returns any) — this is the one
// place that decides whether a message is genuinely a well-formed
// AdminActionResultEvent before anything downstream treats it as one, so a
// malformed or unexpected payload (a future field rename, a bug in the
// backend's own construction) is dropped here rather than reaching
// renderOutcome with fields TypeScript believes are present but aren't.
function isAdminActionResultEvent(data: unknown): data is AdminActionResultEvent {
  if (typeof data !== 'object' || data === null) return false
  const d = data as Record<string, unknown>
  return d.type === 'admin_action_result'
    && typeof d.op_id === 'string'
    && (d.action === 'admin_reset' || d.action === 'welcome_link')
    && typeof d.target_email === 'string'
    && typeof d.state === 'string' && ADMIN_ACTION_RESULT_STATES.has(d.state)
}

const Ctx = createContext<LiveAlertsCtx>(null!)
export const useLiveAlertsContext = () => useContext(Ctx)

const EARLY_RESULT_TTL_MS = 60_000

// Exported for direct unit testing of the curve — the SSE reconnect below
// doesn't hardcode the arithmetic inline so a test doesn't need real
// multi-second waits (or fake timers, unused anywhere else in this test
// suite) just to confirm 1s/2s/4s/8s/16s, capped.
export const SSE_RECONNECT_MAX_BACKOFF_MS = 30_000
export function sseReconnectBackoffMs(attempt: number): number {
  return Math.min(1000 * 2 ** (attempt - 1), SSE_RECONNECT_MAX_BACKOFF_MS)
}

// Distinct from a transport failure: retrying with the same (stale or
// epoch-rotated) token cannot succeed, and a real token change already
// gets a fresh connection via the effect's own dependency array. Exported
// for direct unit testing of the stop-vs-retry branch.
export class SseAuthError extends Error {}

export function LiveAlertsProvider({ children }: { children: ReactNode }) {
  const { token, user, loading } = useAuth()
  const [count, setCount] = useState(0)
  const { show, dismiss, Toast } = useToast()
  const sessionEpoch = useRef(0)
  const pendingOps = useRef(new Map<string, PendingOp>())
  const earlyResults = useRef(new Map<string, { event: AdminActionResultEvent; epoch: number; storedAt: number }>())
  const prevUserId = useRef<number | null>(null)

  // Identity-boundary reset: fires exactly on genuine identity changes
  // (login, logout, different-user login) — never on a same-user token
  // rotation. setToken() (password-change path) does replace the `user`
  // object reference (restoring it alongside the new token — see its own
  // docstring), but never changes its `id`: a self-password-change can't
  // change whose account it is, so `currentUserId` below is unaffected.
  // See spec §4, "This provider now lives above <Routes>...".
  useEffect(() => {
    const currentUserId = user?.id ?? null
    if (currentUserId !== prevUserId.current) {
      prevUserId.current = currentUserId
      sessionEpoch.current += 1
      pendingOps.current.clear()
      earlyResults.current.clear()
      setCount(0)
      dismiss()
    }
  }, [user?.id, dismiss])

  const clear = () => setCount(0)

  const getSessionEpoch = () => sessionEpoch.current

  // Returns whether the op is genuinely still pending after this call.
  // false means either the outcome had already arrived (buffered in
  // earlyResults before the caller even registered) and has just been
  // rendered — the caller must not also show its own "sending…" toast on
  // top of the real, final one renderOutcome just displayed — or the
  // registration was rejected outright as stale (see below).
  const registerPendingOp = (opId: string, entry: PendingOp): boolean => {
    // entry.epoch was captured before this op's own await, at its true
    // start — not read fresh here. If the live counter has since advanced
    // (a logout/login raced this response), the request belongs to a
    // session that's already gone: reject it before any map mutation or
    // toast, exactly like a stale SSE event is dropped below. Checked
    // first, so a stale registration can never resurrect a cleared
    // earlyResults/pendingOps entry either.
    if (entry.epoch !== sessionEpoch.current) return false
    const early = earlyResults.current.get(opId)
    if (early && early.epoch === entry.epoch) {
      earlyResults.current.delete(opId)
      renderOutcome(early.event)
      return false
    }
    if (early) {
      // Epoch mismatch — belongs to a different session. Drop it.
      earlyResults.current.delete(opId)
    }
    pendingOps.current.set(opId, entry)
    return true
  }

  // For an op_id whose HTTP response was itself the settled answer
  // (admission refused: nothing further is coming for it, ever — see
  // AdmissionRefusedEvent's own docstring). The SSE event still gets
  // pushed (dispatch_admin_action always notifies both outcomes), and it
  // carries no information the synchronous response didn't already give
  // the caller — so unlike registerPendingOp, this never renders a toast;
  // it only drops the entry if it happens to have arrived first, rather
  // than leaving it in earlyResults until the next unrelated SSE message
  // opportunistically prunes it (bounded by EARLY_RESULT_TTL_MS, but not
  // guaranteed to run within it if no other admin action's event arrives
  // in the meantime).
  const discardEarlyResult = (opId: string) => {
    earlyResults.current.delete(opId)
  }

  function renderOutcome(event: AdminActionResultEvent) {
    const label = event.target_email
    switch (event.state) {
      case 'admission_refused':
        show(`Could not send to ${label} — too many pending admin actions, try again shortly`, 'err')
        break
      case 'send_unconfirmed':
        show(`Could not confirm the email was sent to ${label}`, 'err')
        break
      case 'outcome_unknown':
        show(`Sent to ${label}, but we couldn't confirm the link is still valid — check manually`, 'err')
        break
      case 'delivered_account_gone':
        show(`Sent to ${label}, but the account was deleted before it could be used`, 'err')
        break
      case 'delivered_superseded':
        show(`Sent to ${label}, but the link is no longer valid`, 'err')
        break
      case 'delivered_live': {
        const verb = event.action === 'welcome_link' ? 'Welcome email' : 'Reset link'
        show(`${verb} sent to ${label}`)
        break
      }
      default:
        // Exhaustiveness check: if a 7th state string is ever added to the
        // backend union without a matching case here, this line fails to
        // compile (event.state narrows to `never` only when every case
        // above is handled) — a stronger guarantee than a runtime default
        // branch.
        event.state satisfies never
    }
  }

  // Connection lifecycle gated on resolved identity, not bare token
  // presence — see spec §4, "Connection lifecycle must be gated on
  // resolved identity". Without the `loading`/`user` guard, a page reload
  // with a stored token would open the connection (and capture
  // sessionEpoch) before `user.id` resolves, then the identity-boundary
  // effect above would immediately bump the epoch, permanently orphaning
  // this connection.
  useEffect(() => {
    if (loading || !token || !user) return
    const controller = new AbortController()
    const connectionEpoch = sessionEpoch.current

    // One connect-and-read attempt. Returns normally on a clean server-
    // initiated close (`done`); throws on any failure — AbortError from
    // `controller.abort()` (unmount, or this effect re-running because
    // token/user/loading changed) alongside a genuine transport failure
    // (DNS, connection reset, server unreachable mid-stream). The caller
    // below is what tells those apart.
    async function connectAndRead(): Promise<void> {
      const res = await fetch('/api/alerts/stream', {
        headers: { Authorization: `Bearer ${token}` },
        signal: controller.signal,
      })
      if (!res.ok) {
        // fetch() only rejects on network-level failure — an HTTP error
        // response (401, 502, 503...) resolves normally, and its short or
        // empty body reaches `done: true` on the very first read().
        // Unchecked, that looked identical to a clean server-initiated
        // close below, which resets the backoff and reconnects
        // immediately: a stale/rotated token, or a proxy returning 502/503
        // under load, produced an unbounded, unbacked-off busy loop of
        // reconnect attempts. 401 specifically won't be fixed by retrying
        // — this same token is sent on every attempt, and a real token
        // change already gets a fresh connection via this effect's own
        // [token, user?.id, loading] dependency array — so it throws a
        // distinct error the catch below recognizes and stops on outright.
        // Every other non-ok status is treated like a transport failure:
        // retried through the same capped exponential backoff.
        if (res.status === 401) {
          throw new SseAuthError()
        }
        throw new Error(`SSE stream request failed with status ${res.status}`)
      }
      const reader = res.body!.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n\n')
        buffer = lines.pop() ?? ''
        for (const chunk of lines) {
          const match = chunk.match(/^data: (.*)$/m)
          if (!match) continue
          // Scoped to just the parse: a malformed payload must not
          // escape further up, which would otherwise be indistinguishable
          // from a genuine transport failure below and either retry a
          // connection that isn't actually broken, or (before that retry
          // existed at all) permanently kill it. The pre-move
          // implementation (Shell.tsx's original useLiveAlerts) wrapped
          // exactly this per-line JSON.parse the same way, ignoring one
          // malformed event and continuing to read the next one; that
          // isolation was dropped when this logic moved here and must stay.
          let data: unknown
          try {
            data = JSON.parse(match[1])
          } catch {
            continue
          }
          if (!data || typeof data !== 'object') continue
          if ((data as { type?: unknown }).type === 'connected') continue
          if (connectionEpoch !== sessionEpoch.current) continue // stale
          if (isAdminActionResultEvent(data)) {
            const pending = pendingOps.current.get(data.op_id)
            // pending.epoch is the epoch the *registering request*
            // started under, which can differ from this connection's own
            // captured epoch: an op registered just before a logout, then
            // the identity-boundary reset clears pendingOps and a new
            // connection opens under the new epoch — if that new
            // connection's SSE stream happened to redeliver (or a lagging
            // buffered chunk from the old connection somehow still
            // matched by op_id) an event for the old op_id, matching on
            // op_id alone would resurrect a stale operation. Checked
            // before any mutation or toast, same as the registration-time
            // guard above.
            if (pending && pending.epoch === connectionEpoch) {
              pendingOps.current.delete(data.op_id)
              pending.dismiss()
              renderOutcome(data)
            } else if (pending) {
              // Stale entry under an old epoch — drop it without acting.
              pendingOps.current.delete(data.op_id)
            } else {
              earlyResults.current.set(data.op_id, {
                event: data, epoch: connectionEpoch, storedAt: Date.now(),
              })
              // Prune stale unclaimed entries opportunistically.
              for (const [k, v] of earlyResults.current) {
                if (Date.now() - v.storedAt > EARLY_RESULT_TTL_MS) {
                  earlyResults.current.delete(k)
                }
              }
            }
            continue
          }
          setCount(n => n + 1)
        }
      }
    }

    // Retries a genuine transport failure (network drop, server
    // unreachable, connection reset) with capped exponential backoff —
    // distinguished from an intentional abort (`controller.abort()` on
    // unmount, or this whole effect re-running for a real identity
    // change) by `error.name === 'AbortError'`, the standard name both
    // `fetch` and a reader's `read()` throw with when their own signal
    // fired. Retrying under the SAME connectionEpoch/controller is
    // correct here specifically because no identity change occurred —
    // sessionEpoch, pendingOps and earlyResults all still describe the
    // one session this connection belongs to; only the transport broke.
    // A prior version of this effect let ANY exception here — abort or
    // otherwise — permanently end the read loop with no reconnect, since
    // the effect's own dependencies ([token, user?.id, loading]) have no
    // reason to change just because the network blipped: a transient
    // failure silently and permanently lost live delivery for the rest of
    // the session.
    //
    // Retries indefinitely at the same exponential-then-capped backoff —
    // an earlier version gave up after 5 attempts (~31s total), which
    // reproduced the exact bug this loop exists to fix, just with a longer
    // fuse: any outage lasting longer than that (a deploy, a brief infra
    // blip) silently and permanently disabled live delivery for the rest
    // of an otherwise perfectly valid session, with no path back short of
    // a full page reload. Live alerts are a background nicety, not
    // something that should ever go dark for a still-logged-in user — the
    // 30s backoff ceiling already bounds how often a truly-dead server
    // gets hit. Only three things still end this loop: an intentional
    // abort (above), an auth failure (below — retrying with the same
    // stale token can never succeed), or the effect re-running for a real
    // identity/token change (its own dependency array).
    let attempt = 0
    void (async () => {
      while (!controller.signal.aborted) {
        try {
          await connectAndRead()
          // A clean, server-initiated close (`done`) is not a failure —
          // but it is NOT distinguishable, from here, from a broken
          // proxy/server that returns HTTP 200 with an immediately-closed
          // or empty stream on every single attempt: res.ok is true (this
          // is not the HTTP-error path above), so reader.read() just
          // returns {done: true} on its very first call and
          // connectAndRead() returns normally, exactly like a real,
          // healthy connection the server closed after a normal
          // idle-timeout or recycle. Reconnecting with NO delay at all in
          // that case is an unbounded, unthrottled fetch loop against a
          // server that is never going to behave differently — reproduced
          // directly. Applying the same first backoff step
          // (sseReconnectBackoffMs(1)) here, then resetting the counter
          // once that single wait has elapsed, bounds the loop to roughly
          // one request per backoff-floor interval without materially
          // delaying the case this is NOT: a healthy, long-lived
          // connection recycling normally, where a ~1s wait before
          // reconnecting is immaterial for a background live-alerts
          // stream. Deliberately NOT the same escalating counter a real
          // failure streak uses — a run of clean EOFs stays at the first
          // step every time rather than climbing toward the 30s ceiling,
          // since each one did, genuinely, deliver a working connection.
          await new Promise(resolve => setTimeout(resolve, sseReconnectBackoffMs(1)))
          attempt = 0
        } catch (err) {
          if (controller.signal.aborted || (err as Error)?.name === 'AbortError') {
            return
          }
          if (err instanceof SseAuthError) {
            // Stop outright — retrying with the same (stale or
            // epoch-rotated) token can never succeed, and a real token
            // change already gets a fresh connection via this effect's
            // own [token, user?.id, loading] dependency array.
            return
          }
          attempt += 1
          await new Promise(resolve => setTimeout(resolve, sseReconnectBackoffMs(attempt)))
        }
      }
    })()
    return () => controller.abort()
  }, [token, user?.id, loading])

  return (
    <Ctx.Provider value={{ count, clear, Toast, registerPendingOp, discardEarlyResult, getSessionEpoch }}>
      {children}
    </Ctx.Provider>
  )
}
