/**
 * useAuth's setToken — the fix's other half.
 *
 * setToken must update *observable* React state (the `token` field
 * exposed by useAuth), not only localStorage — anything reacting to a
 * replacement token (useLiveAlerts' SSE stream; see
 * useLiveAlertsReconnect.test.tsx) depends on that state, and a caller
 * that only wrote to localStorage would never actually notify it.
 */
import { render, screen, waitFor, act } from '@testing-library/react'
import { useEffect } from 'react'
import { vi, beforeEach, afterEach, describe, it, expect } from 'vitest'
import type { User } from '@/lib/api'

vi.mock('@/lib/api', () => ({
  api: {
    auth: { me: vi.fn(), login: vi.fn(), totpVerify: vi.fn() },
  },
}))

import { api } from '@/lib/api'
import { AuthProvider, useAuth } from '@/hooks/useAuth'

const ORIGINAL_USER: User = {
  id: 1, email: 'a@b.com', display_name: 'A', role: 'viewer',
  is_active: true, totp_enabled: false, created_at: '2024-01-01T00:00:00Z',
  has_outstanding_welcome_token: false,
}
// A fresh User object setToken would receive from a real PATCH response —
// same id (a self-password-change can't change whose account it is), a
// changed field to prove this is the NEW object and not the stale one
// api.auth.me()'s mount-only fetch already installed.
const REPLACEMENT_USER: User = { ...ORIGINAL_USER, display_name: 'A (renamed)' }

function Probe() {
  const { token, user, setToken, getAuthGeneration } = useAuth()
  // Capturing getAuthGeneration() at click time, not up front — mirrors
  // SecurityModal.savePassword's own discipline (captured right before
  // starting the async request this stands in for), which matters for
  // the generation-guard tests further below: they need each click to
  // observe whatever the CURRENT generation is at that moment, not one
  // fixed at first render.
  return (
    <div>
      <div data-testid="token">{token ?? 'null'}</div>
      <div data-testid="user">{user?.display_name ?? 'null'}</div>
      <button type="button" onClick={() => setToken('replacement-token', REPLACEMENT_USER, getAuthGeneration())}>
        replace
      </button>
    </div>
  )
}

describe('useAuth setToken', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.mocked(api.auth.me).mockResolvedValue(ORIGINAL_USER)
  })

  afterEach(() => {
    localStorage.clear()
  })

  it('updates the observable token value, not only localStorage', async () => {
    localStorage.setItem('token', 'original-token')
    render(<AuthProvider><Probe /></AuthProvider>)

    await waitFor(() => expect(screen.getByTestId('token')).toHaveTextContent('original-token'))

    screen.getByRole('button', { name: 'replace' }).click()

    await waitFor(() => expect(screen.getByTestId('token')).toHaveTextContent('replacement-token'))
    expect(localStorage.getItem('token')).toBe('replacement-token')
  })

  it('also restores the fresh user, not just the token', async () => {
    // Regression: setToken used to accept only the access token, leaving
    // `user` untouched. That was fine when nothing else could have
    // cleared `user` first — but a concurrent stale-401 race (see the
    // describe block below) can null it out in the window before this
    // call runs, and a token-only setToken would then never restore it,
    // stranding a valid session with `user: null` — which Guard (App.tsx)
    // treats as logged out.
    localStorage.setItem('token', 'original-token')
    render(<AuthProvider><Probe /></AuthProvider>)
    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('A'))

    screen.getByRole('button', { name: 'replace' }).click()

    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('A (renamed)'))
  })
})

describe('useAuth auth:unauthorized race with a concurrent setToken', () => {
  // Regression: a self-password-change bumps the account's token_epoch
  // server-side, immediately invalidating every token issued before it —
  // including one already in flight on a DIFFERENT, concurrent request
  // (e.g. Dashboard polling) that started before the change. That older
  // request's 401 is real, but only for its own (now-superseded) token —
  // by the time its 401 arrives, setToken may have already installed the
  // replacement from the password-change response itself. Without
  // checking which token actually failed, api.ts's global
  // 'auth:unauthorized' dispatch was treated as "the whole session is
  // dead," and this handler wiped out the brand new, still-valid token
  // and logged the user out right after telling them "Password changed."
  beforeEach(() => {
    localStorage.clear()
    vi.mocked(api.auth.me).mockResolvedValue({
      id: 1, email: 'a@b.com', display_name: 'A', role: 'viewer',
      is_active: true, totp_enabled: false, created_at: '2024-01-01T00:00:00Z',
      has_outstanding_welcome_token: false,
    })
  })

  afterEach(() => {
    localStorage.clear()
  })

  it('ignores a 401 reported for a token that has already been superseded', async () => {
    localStorage.setItem('token', 'original-token')
    render(<AuthProvider><Probe /></AuthProvider>)
    await waitFor(() => expect(screen.getByTestId('token')).toHaveTextContent('original-token'))

    // The password-change PATCH's own response installs the replacement
    // token — this happens synchronously from the app's point of view,
    // before the older in-flight request's (delayed) 401 is even
    // processed.
    screen.getByRole('button', { name: 'replace' }).click()
    await waitFor(() => expect(screen.getByTestId('token')).toHaveTextContent('replacement-token'))

    // The older request's 401 arrives late, carrying the OLD token it
    // actually authenticated with — api.ts's request() reads this from
    // its own local `token` variable, captured before the request was
    // sent, not from (the now-different) localStorage.
    act(() => {
      window.dispatchEvent(new CustomEvent('auth:unauthorized', { detail: { token: 'original-token' } }))
    })

    // Must NOT log out — the current, replacement token is still valid;
    // this stale 401 says nothing about it.
    await new Promise(r => setTimeout(r, 10))
    expect(screen.getByTestId('token')).toHaveTextContent('replacement-token')
    expect(localStorage.getItem('token')).toBe('replacement-token')
  })

  it('still logs out on a 401 for the token that is actually current', async () => {
    localStorage.setItem('token', 'only-token')
    render(<AuthProvider><Probe /></AuthProvider>)
    await waitFor(() => expect(screen.getByTestId('token')).toHaveTextContent('only-token'))

    act(() => {
      window.dispatchEvent(new CustomEvent('auth:unauthorized', { detail: { token: 'only-token' } }))
    })

    await waitFor(() => expect(screen.getByTestId('token')).toHaveTextContent('null'))
    expect(localStorage.getItem('token')).toBeNull()
  })

  it('recovers user even when the stale 401 arrives BEFORE setToken runs', async () => {
    // The opposite ordering from the test above, and the one that
    // actually breaks a token-only setToken: the older in-flight
    // request's stale 401 (still carrying the pre-change token) arrives
    // and is processed FIRST — while it is still the token in
    // localStorage, since the password-change PATCH response (and this
    // component's own setToken call, standing in for SecurityModal's)
    // hasn't arrived yet. At that moment the guard in useAuth's handler
    // sees a match and correctly clears token/user — correctly, because
    // from its point of view nothing has superseded that token yet.
    //
    // setToken() then runs microtasks later (the real PATCH response
    // finally arriving). If it only restored `token`, `user` would stay
    // null forever with a valid token in place — Guard (App.tsx) checks
    // `user`, not `token`, so it would redirect to /login despite a
    // valid session. Restoring both together is what makes the final
    // state correct regardless of which arrived first.
    localStorage.setItem('token', 'original-token')
    render(<AuthProvider><Probe /></AuthProvider>)
    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('A'))

    act(() => {
      window.dispatchEvent(new CustomEvent('auth:unauthorized', { detail: { token: 'original-token' } }))
    })
    await waitFor(() => expect(screen.getByTestId('token')).toHaveTextContent('null'))
    expect(screen.getByTestId('user')).toHaveTextContent('null')

    // The password-change response arrives after the stale 401 was
    // already processed — exactly the ordering this test targets.
    screen.getByRole('button', { name: 'replace' }).click()

    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('A (renamed)'))
    expect(screen.getByTestId('token')).toHaveTextContent('replacement-token')
  })

  it('a stale 401 during an in-flight password change does not reject the still-pending setToken call', async () => {
    // Regression in the auth:unauthorized generation bump itself (added to
    // fix a DIFFERENT race — see the "generation bumped BEFORE the
    // trailing me() call" describe block below): SecurityModal.
    // savePassword captures getAuthGeneration() BEFORE its PATCH starts,
    // using the pre-change token — matching real production discipline,
    // unlike Probe's `replace` button above, which captures it at click
    // time (AFTER any 401 in these tests) and so cannot catch this. If the
    // handler bumps the generation when it clears state for this exact
    // token, the generation captured before the PATCH is stale by the
    // time the PATCH response arrives, and setToken's own guard rejects
    // the valid replacement — leaving the user logged out after a
    // SUCCESSFUL password change, exactly what beginPasswordChange exists
    // to prevent for a different failure mode.
    localStorage.setItem('token', 'original-token')
    render(<AuthProvider><GenerationRaceProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('A'))

    const auth = (window as any).__authForTest
    expect(auth.beginPasswordChange()).toBe(true)
    // Captured BEFORE the 401, exactly like SecurityModal.savePassword
    // captures it before its own await api.users.update(...) call.
    const preChangeGeneration = auth.getAuthGeneration()

    // An unrelated in-flight request, still using the pre-change token,
    // 401s after set_password already bumped token_epoch server-side but
    // before this PATCH's own response (carrying the replacement token)
    // has arrived.
    act(() => {
      window.dispatchEvent(new CustomEvent('auth:unauthorized', { detail: { token: 'original-token' } }))
    })
    await waitFor(() => expect(screen.getByTestId('token')).toHaveTextContent('null'))

    // The PATCH response now arrives, carrying the real replacement token
    // — using the generation captured BEFORE the 401 above.
    act(() => {
      auth.setToken('replacement-token', REPLACEMENT_USER, preChangeGeneration)
    })

    await waitFor(() => expect(screen.getByTestId('token')).toHaveTextContent('replacement-token'))
    expect(screen.getByTestId('user')).toHaveTextContent('A (renamed)')
  })
})

// A fresh User for a SECOND, independent password-change save — distinct
// display_name from both ORIGINAL_USER and REPLACEMENT_USER, so a test can
// tell exactly which of two saves' result ended up installed.
const SECOND_SAVE_USER: User = { ...ORIGINAL_USER, display_name: 'A (second save)' }

/** Exposes the raw pieces (capture the generation now, call setToken with
 * it later, read `user`/`token`) rather than one fixed button — needed to
 * drive two independent "saves" against the SAME provider instance and
 * control exactly when each one's setToken call actually happens, the way
 * two real SecurityModal mounts racing each other would. Captured onto
 * `window` in an effect, not during render (assigning to something
 * outside the component during render is itself a side effect React
 * correctly flags) — mirrors loginRedirectRace.test.tsx's own
 * SetTokenCapture pattern for the identical need. */
function GenerationRaceProbe() {
  const auth = useAuth()
  useEffect(() => {
    (window as any).__authForTest = auth
  })
  return (
    <div>
      <div data-testid="token">{auth.token ?? 'null'}</div>
      <div data-testid="user">{auth.user?.display_name ?? 'null'}</div>
    </div>
  )
}

describe('useAuth setToken generation guard — two independent SecurityModal saves', () => {
  // Regression: SecurityModal stays dismissible while a save is in
  // flight (closing it unmounts that instance; reopening mounts a fresh
  // one with its own local state), so two independent savePassword()
  // calls can each have their own PATCH in flight against the SAME
  // AuthProvider at once. Whichever response resolved LAST used to win
  // unconditionally — installing an OLDER change's token/user after a
  // NEWER one already landed. The generation guard closes this: each
  // caller captures getAuthGeneration() before its own request starts,
  // and setToken silently ignores a call whose captured generation no
  // longer matches current state.
  beforeEach(() => {
    localStorage.clear()
    vi.mocked(api.auth.me).mockResolvedValue(ORIGINAL_USER)
  })

  afterEach(() => {
    localStorage.clear()
    delete (window as any).__authForTest
  })

  it('an older save resolving AFTER a newer one does not overwrite the newer session', async () => {
    localStorage.setItem('token', 'original-token')
    render(<AuthProvider><GenerationRaceProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('A'))

    // Save A "starts": captures the generation before anything else has
    // written to the provider.
    const authAtStartOfA = (window as any).__authForTest
    const generationA = authAtStartOfA.getAuthGeneration()

    // Save B starts and finishes completely first — the modal was closed
    // and reopened in between, so this is a fresh instance with its own
    // captured generation.
    const generationB = (window as any).__authForTest.getAuthGeneration()
    act(() => {
      (window as any).__authForTest.setToken('token-from-B', SECOND_SAVE_USER, generationB)
    })
    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('A (second save)'))

    // Save A's response NOW arrives — later than B's, carrying the
    // generation captured before B ever ran.
    act(() => {
      (window as any).__authForTest.setToken('token-from-A', REPLACEMENT_USER, generationA)
    })

    // B's result must still be in place — A's stale write was ignored.
    await new Promise(r => setTimeout(r, 10))
    expect(screen.getByTestId('user')).toHaveTextContent('A (second save)')
    expect(screen.getByTestId('token')).toHaveTextContent('token-from-B')
    expect(localStorage.getItem('token')).toBe('token-from-B')
  })

  it('a save resolving after an explicit logout does not silently log the user back in', async () => {
    localStorage.setItem('token', 'original-token')
    render(<AuthProvider><GenerationRaceProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('A'))

    // The change "starts": generation captured before the logout below.
    const generationAtStart = (window as any).__authForTest.getAuthGeneration()

    // The user explicitly signs out while that change is still in flight.
    act(() => {
      (window as any).__authForTest.logout()
    })
    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('null'))

    // The change's response NOW arrives, carrying the pre-logout generation.
    act(() => {
      (window as any).__authForTest.setToken('token-from-stale-save', REPLACEMENT_USER, generationAtStart)
    })

    // Must stay logged out — an explicit logout must never be silently
    // undone by an older, still-in-flight operation's response.
    await new Promise(r => setTimeout(r, 10))
    expect(screen.getByTestId('user')).toHaveTextContent('null')
    expect(screen.getByTestId('token')).toHaveTextContent('null')
    expect(localStorage.getItem('token')).toBeNull()
  })

  it('a save started AFTER the current generation still installs correctly', async () => {
    // Sanity check against the guard being too aggressive: a save with no
    // competing write in between must still succeed normally.
    localStorage.setItem('token', 'original-token')
    render(<AuthProvider><GenerationRaceProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('A'))

    const generation = (window as any).__authForTest.getAuthGeneration()
    act(() => {
      (window as any).__authForTest.setToken('replacement-token', REPLACEMENT_USER, generation)
    })

    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('A (renamed)'))
    expect(screen.getByTestId('token')).toHaveTextContent('replacement-token')
    expect(localStorage.getItem('token')).toBe('replacement-token')
  })
})

/** Exposes beginPasswordChange/endPasswordChange directly, captured the
 * same way GenerationRaceProbe captures the rest of useAuth — needed to
 * drive the lock from outside any component's own render cycle, the way
 * two independent SecurityModal instances (or one instance and a plain
 * test assertion) would each call it. */
function PasswordChangeLockProbe() {
  const auth = useAuth()
  useEffect(() => {
    (window as any).__authForTest = auth
  })
  return null
}

describe('useAuth beginPasswordChange/endPasswordChange — serializing overlapping password changes', () => {
  // Regression this specifically closes, found as a P2 follow-up to the
  // generation guard above: that guard picks whichever setToken call
  // ARRIVES LAST (by whatever order the two callers happen to invoke it
  // in), which is not necessarily the same as whichever password change
  // COMMITTED LAST on the server. set_password bumps token_epoch
  // unconditionally on every call, and the epoch check (api/deps.py) is
  // exact equality — so only the token from the truly-latest commit is
  // ever valid, an ordering the browser cannot infer from network
  // arrival order alone. Two overlapping SecurityModal saves (the modal
  // stays dismissible while one is in flight; reopening starts a
  // genuinely independent second request before the first has resolved)
  // could previously have the generation guard keep the FIRST-ARRIVING
  // response even when the SECOND-ARRIVING one was the server's real
  // current winner, leaving the browser holding a token that 401s on its
  // very next request. Serializing at the source — never let a second
  // change start while one is already in flight — removes the ambiguity
  // entirely rather than guessing after the fact.
  beforeEach(() => {
    localStorage.clear()
    vi.mocked(api.auth.me).mockResolvedValue(ORIGINAL_USER)
  })

  afterEach(() => {
    localStorage.clear()
    delete (window as any).__authForTest
  })

  it('refuses a second beginPasswordChange while the first is still in flight', async () => {
    render(<AuthProvider><PasswordChangeLockProbe /></AuthProvider>)
    await waitFor(() => expect((window as any).__authForTest).toBeDefined())

    const first = (window as any).__authForTest.beginPasswordChange()
    const second = (window as any).__authForTest.beginPasswordChange()

    expect(first).toBe(true)
    expect(second).toBe(false)
  })

  it('allows a new change once the in-flight one calls endPasswordChange', async () => {
    render(<AuthProvider><PasswordChangeLockProbe /></AuthProvider>)
    await waitFor(() => expect((window as any).__authForTest).toBeDefined())

    expect((window as any).__authForTest.beginPasswordChange()).toBe(true)
    expect((window as any).__authForTest.beginPasswordChange()).toBe(false)

    act(() => {
      (window as any).__authForTest.endPasswordChange()
    })

    expect((window as any).__authForTest.beginPasswordChange()).toBe(true)
  })

  it('releases the lock even after a failed change, so a retry is not permanently blocked', async () => {
    // Mirrors Shell.tsx's own finally { ...; endPasswordChange() } — the
    // release must happen regardless of whether the request that held
    // the lock succeeded or failed.
    render(<AuthProvider><PasswordChangeLockProbe /></AuthProvider>)
    await waitFor(() => expect((window as any).__authForTest).toBeDefined())

    expect((window as any).__authForTest.beginPasswordChange()).toBe(true)
    // Simulates savePassword's own catch/finally: the request failed, but
    // the lock is still released unconditionally.
    act(() => {
      (window as any).__authForTest.endPasswordChange()
    })

    expect((window as any).__authForTest.beginPasswordChange()).toBe(true)
  })
})

const LOGIN_USER: User = { ...ORIGINAL_USER, display_name: 'Freshly logged in' }

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(r => { resolve = r })
  return { promise, resolve }
}

describe('useAuth login/completeTotp — generation bumped BEFORE the trailing me() call', () => {
  // Regression: login()/completeTotp() used to publish the new token
  // (localStorage + setTokenState) and only bump authGeneration AFTER
  // their own trailing api.auth.me() call resolved. For the whole
  // duration of that await, the generation was still whatever it was
  // BEFORE this login — an older, still-in-flight setToken call (e.g.
  // from a password change under the PREVIOUS session, captured under
  // that same generation) could still pass setToken's check during that
  // window, overwriting the token this login just published with a stale
  // one. This login's own setUser(await me()) then landed on top of it —
  // a live user paired with the WRONG token, which 401s on the very next
  // request.
  beforeEach(() => {
    localStorage.clear()
    vi.mocked(api.auth.me).mockResolvedValue(ORIGINAL_USER)
  })

  afterEach(() => {
    localStorage.clear()
    delete (window as any).__authForTest
  })

  it('login() closes the window: a stale setToken during its own me() call is rejected', async () => {
    localStorage.setItem('token', 'pre-existing-token')
    render(<AuthProvider><GenerationRaceProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('A'))

    // The stale write's generation, captured before login() ever runs —
    // stands in for a password-change save that started under the
    // PREVIOUS session and is still in flight.
    const staleGeneration = (window as any).__authForTest.getAuthGeneration()

    const me = deferred<User>()
    vi.mocked(api.auth.me).mockReturnValueOnce(me.promise)
    vi.mocked(api.auth.login).mockResolvedValueOnce({ access_token: 'login-token' } as any)

    const loginPromise = (window as any).__authForTest.login('a@b.com', 'password')
    // login() has resolved its own api.auth.login() and published the
    // token by now, but is still awaiting api.auth.me() — exactly the
    // window this fix closes.
    await waitFor(() => expect(localStorage.getItem('token')).toBe('login-token'))

    // The stale password-change response "arrives" during that window.
    act(() => {
      (window as any).__authForTest.setToken('stale-token-from-old-session', REPLACEMENT_USER, staleGeneration)
    })

    // Must be rejected: the token this login() just published must
    // survive, not be overwritten by the older write.
    expect(localStorage.getItem('token')).toBe('login-token')

    // login()'s own me() now resolves.
    act(() => { me.resolve(LOGIN_USER) })
    await loginPromise
    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('Freshly logged in'))
    // The token must match the user actually installed — not the stale
    // write's mismatched pair.
    expect(localStorage.getItem('token')).toBe('login-token')
  })

  it("login()'s own delayed me() result is dropped if superseded before it resolves", async () => {
    // The other direction: something ELSE advances the generation again
    // while login()'s own me() is still in flight (e.g. a logout) — that
    // later write already reflects the true current state, and login()'s
    // own now-stale me() result must not overwrite it.
    localStorage.setItem('token', 'pre-existing-token')
    render(<AuthProvider><GenerationRaceProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('A'))

    const me = deferred<User>()
    vi.mocked(api.auth.me).mockReturnValueOnce(me.promise)
    vi.mocked(api.auth.login).mockResolvedValueOnce({ access_token: 'login-token' } as any)

    const loginPromise = (window as any).__authForTest.login('a@b.com', 'password')
    await waitFor(() => expect(localStorage.getItem('token')).toBe('login-token'))

    // The user logs out again before login()'s own me() call resolves.
    act(() => {
      (window as any).__authForTest.logout()
    })
    await waitFor(() => expect(screen.getByTestId('token')).toHaveTextContent('null'))

    // login()'s delayed me() result now arrives.
    act(() => { me.resolve(LOGIN_USER) })
    await loginPromise

    // Must still be logged out — login()'s own stale result must not
    // resurrect a session the user already left.
    await new Promise(r => setTimeout(r, 10))
    expect(screen.getByTestId('user')).toHaveTextContent('null')
  })

  it('completeTotp() closes the same window as login()', async () => {
    // Identical race, different entry point: completeTotp() is the OTHER
    // place that used to publish a token/state and only bump the
    // generation after its own trailing me() call — a TOTP-verify
    // completing a login has the exact same window as a plain
    // credential-only login does.
    localStorage.setItem('token', 'pre-existing-token')
    render(<AuthProvider><GenerationRaceProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('A'))

    const staleGeneration = (window as any).__authForTest.getAuthGeneration()

    const me = deferred<User>()
    vi.mocked(api.auth.me).mockReturnValueOnce(me.promise)
    vi.mocked(api.auth.totpVerify).mockResolvedValueOnce({ access_token: 'totp-token' } as any)

    const completeTotpPromise = (window as any).__authForTest.completeTotp('session-token', '123456')
    await waitFor(() => expect(localStorage.getItem('token')).toBe('totp-token'))

    act(() => {
      (window as any).__authForTest.setToken('stale-token-from-old-session', REPLACEMENT_USER, staleGeneration)
    })
    expect(localStorage.getItem('token')).toBe('totp-token')

    act(() => { me.resolve(LOGIN_USER) })
    await completeTotpPromise
    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('Freshly logged in'))
    expect(localStorage.getItem('token')).toBe('totp-token')
  })

  it("a 401 clearing the session while login()'s own me() is still in flight is not silently undone", async () => {
    // Regression: the auth:unauthorized handler used to clear token/user
    // without bumping authGeneration. If some OTHER request — issued using
    // the token this login() just installed — 401s while login()'s own
    // trailing me() call is still pending, the handler correctly clears
    // the session (the failed token matches localStorage's current one),
    // but login()'s generation check at the end still saw an UNCHANGED
    // generation and let its delayed setUser(freshUser) silently
    // repopulate `user` right after — Guard (App.tsx) checks `user`, not
    // `token`, so it would treat the client as authenticated despite
    // localStorage holding no token at all.
    localStorage.setItem('token', 'pre-existing-token')
    render(<AuthProvider><GenerationRaceProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('A'))

    const me = deferred<User>()
    vi.mocked(api.auth.me).mockReturnValueOnce(me.promise)
    vi.mocked(api.auth.login).mockResolvedValueOnce({ access_token: 'login-token' } as any)

    const loginPromise = (window as any).__authForTest.login('a@b.com', 'password')
    await waitFor(() => expect(localStorage.getItem('token')).toBe('login-token'))

    // Some other in-flight request, using the token login() just
    // installed, comes back 401 while login()'s own me() is still pending.
    act(() => {
      window.dispatchEvent(new CustomEvent('auth:unauthorized', { detail: { token: 'login-token' } }))
    })
    await waitFor(() => expect(localStorage.getItem('token')).toBe(null))
    expect(screen.getByTestId('user')).toHaveTextContent('null')

    // login()'s own me() now resolves — its result must be dropped, not
    // resurrect the session the 401 just correctly cleared.
    act(() => { me.resolve(LOGIN_USER) })
    await loginPromise
    await new Promise(r => setTimeout(r, 10))
    expect(screen.getByTestId('user')).toHaveTextContent('null')
    expect(localStorage.getItem('token')).toBe(null)
  })

  it("completeTotp() closes the same auth:unauthorized window as login()", async () => {
    // Identical race, different entry point — completeTotp() shares the
    // exact same generation-check mechanism as login() (see its own
    // comment above), so the auth:unauthorized fix that closes this for
    // login() must close it here too, not just by inference.
    localStorage.setItem('token', 'pre-existing-token')
    render(<AuthProvider><GenerationRaceProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('A'))

    const me = deferred<User>()
    vi.mocked(api.auth.me).mockReturnValueOnce(me.promise)
    vi.mocked(api.auth.totpVerify).mockResolvedValueOnce({ access_token: 'totp-token' } as any)

    const completeTotpPromise = (window as any).__authForTest.completeTotp('session-token', '123456')
    await waitFor(() => expect(localStorage.getItem('token')).toBe('totp-token'))

    // Some other in-flight request, using the token completeTotp() just
    // installed, comes back 401 while its own me() is still pending.
    act(() => {
      window.dispatchEvent(new CustomEvent('auth:unauthorized', { detail: { token: 'totp-token' } }))
    })
    await waitFor(() => expect(localStorage.getItem('token')).toBe(null))
    expect(screen.getByTestId('user')).toHaveTextContent('null')

    // completeTotp()'s own me() now resolves — its result must be
    // dropped, not resurrect the session the 401 just correctly cleared.
    act(() => { me.resolve(LOGIN_USER) })
    await completeTotpPromise
    await new Promise(r => setTimeout(r, 10))
    expect(screen.getByTestId('user')).toHaveTextContent('null')
    expect(localStorage.getItem('token')).toBe(null)
  })

  it('a stale in-flight password change does not suppress the bump for a LATER, unrelated login', async () => {
    // Regression in the password-change 401 fix itself (see the
    // "auth:unauthorized race with a concurrent setToken" describe block
    // above): beginPasswordChange used to set a plain boolean flag that
    // stayed true for as long as the original PATCH promise was
    // unsettled — which a logout and a fresh login do NOT cancel, since
    // that promise is not tied to any component's lifecycle at all. A 401
    // arriving during a LATER login's own me() call would then still see
    // "a password change is in flight" and wrongly skip the bump meant to
    // protect THAT login — resurrecting its user after its token was
    // correctly cleared, the exact bug the bump exists to close two
    // entries up. The fix must key off the generation the password change
    // actually started with, not merely whether one is outstanding.
    localStorage.setItem('token', 'pre-existing-token')
    render(<AuthProvider><GenerationRaceProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByTestId('user')).toHaveTextContent('A'))

    const auth = (window as any).__authForTest
    // A password change starts and never resolves in this test — standing
    // in for its PATCH promise still being in flight (or having settled
    // without endPasswordChange ever running, which the real code always
    // does via `finally`, but the ref itself does not know that on its
    // own — only a fresh write moving the generation past it can).
    expect(auth.beginPasswordChange()).toBe(true)

    // The user explicitly logs out — a legitimate write, bumps the
    // generation past what beginPasswordChange captured.
    act(() => { auth.logout() })
    await waitFor(() => expect(screen.getByTestId('token')).toHaveTextContent('null'))

    // A fresh login starts — a DIFFERENT session, unrelated to the stale
    // password change above.
    const me = deferred<User>()
    vi.mocked(api.auth.me).mockReturnValueOnce(me.promise)
    vi.mocked(api.auth.login).mockResolvedValueOnce({ access_token: 'fresh-login-token' } as any)
    const loginPromise = auth.login('a@b.com', 'password')
    await waitFor(() => expect(localStorage.getItem('token')).toBe('fresh-login-token'))

    // An unrelated request, using the fresh login's own token, 401s while
    // its me() call is still pending — nothing to do with the stale
    // password change above, which never called endPasswordChange.
    act(() => {
      window.dispatchEvent(new CustomEvent('auth:unauthorized', { detail: { token: 'fresh-login-token' } }))
    })
    await waitFor(() => expect(localStorage.getItem('token')).toBe(null))
    expect(screen.getByTestId('user')).toHaveTextContent('null')

    // The fresh login's own me() now resolves — must be dropped, not
    // resurrect the session the 401 just correctly cleared. If the stale
    // password-change flag had wrongly suppressed the bump above, this
    // would incorrectly show "Freshly logged in" instead.
    act(() => { me.resolve(LOGIN_USER) })
    await loginPromise
    await new Promise(r => setTimeout(r, 10))
    expect(screen.getByTestId('user')).toHaveTextContent('null')
    expect(localStorage.getItem('token')).toBe(null)
  })
})
