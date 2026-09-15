import { createContext, useContext, useState, useEffect, useRef, ReactNode } from 'react'
import { api, User, TotpChallenge } from '@/lib/api'

interface AuthCtx {
  user: User | null
  loading: boolean
  /** The current access token, or null when signed out. Mirrors
   *  localStorage but as observable React state — anything that needs to
   *  react to a *replaced* token (not just its initial presence), such as
   *  useLiveAlerts' SSE stream below, must depend on this rather than
   *  reading localStorage directly in a mount-only effect. */
  token: string | null
  login: (email: string, password: string) => Promise<TotpChallenge | null>
  completeTotp: (sessionToken: string, code: string) => Promise<void>
  logout: () => void
  /** Installs a replacement access token and the fresh `User` it belongs
   *  to, without a full re-login — for PATCH /users/{id}'s own response
   *  when the caller just changed their own password (which invalidates
   *  the token that authenticated that very request). Updates `token` too,
   *  not just localStorage — see its own note above: a caller only reading
   *  localStorage would never observe this replacement and would keep
   *  using the now-stale token until it happened to remount.
   *
   *  Restoring `user` here too (not just `token`) closes a race with the
   *  `auth:unauthorized` handler below: an older, still-in-flight request
   *  that started before this same password change — using the
   *  now-superseded token — can have its stale 401 arrive and clear
   *  `user` to null in the window before this call runs (the PATCH
   *  response this token/user pair comes from is still in flight at that
   *  point). If this only restored `token`, `user` would stay null with a
   *  perfectly valid token in place — `Guard` (App.tsx) checks `user`, not
   *  `token`, so it would redirect to /login despite a valid session.
   *  Since this call is always the eventual result of the very same
   *  password-change response that made the old token stale, it reliably
   *  runs after any such stale 401 for that rotation — restoring both
   *  fields together here is what makes the final state correct
   *  regardless of which arrives first.
   *
   *  `expectedGeneration` guards a DIFFERENT race than the one above: an
   *  explicit `logout()` (or a fresh `login()`/`completeTotp()`) landing
   *  while this call's own request is still in flight means the caller's
   *  result is no longer the truth to install — the user's own explicit
   *  action must never be silently undone by an older operation's response
   *  arriving afterward. Callers capture `getAuthGeneration()` before
   *  starting their own async request and pass it back here; this call is
   *  silently ignored if the generation has since moved on (any call to
   *  setToken/logout/login/completeTotp bumps it).
   *
   *  This is NOT sufficient, on its own, to pick between two overlapping
   *  password changes correctly — see `beginPasswordChange`'s own
   *  docstring for why arrival order at the browser is not the same thing
   *  as commit order on the server, and why THAT race needs serialization
   *  rather than a generation check. */
  setToken: (accessToken: string, user: User, expectedGeneration: number) => void
  /** Current auth-state write generation — bumped by every call to
   *  setToken/logout/login/completeTotp. Capture this before starting an
   *  async operation that will later call setToken, so that call can
   *  detect being superseded by a newer write in the meantime. See
   *  setToken's own docstring for the race this exists to close. */
  getAuthGeneration: () => number
  /** Reserves the single "a self-password-change is in flight" slot.
   *  Returns true if the caller now holds it (must call
   *  `endPasswordChange()` exactly once when its request settles, success
   *  or failure alike), false if another change is already in flight — in
   *  which case the caller must not start its own request at all.
   *
   *  Exists because the generation guard on `setToken` picks whichever
   *  RESPONSE ARRIVES AT THE BROWSER FIRST, which is not the same
   *  ordering as which request COMMITTED LAST ON THE SERVER — set_password
   *  bumps token_epoch unconditionally on every call, and the epoch check
   *  (api/deps.py) is exact equality, so only the token from the LATEST
   *  commit is ever valid, regardless of network arrival-order jitter.
   *  Two overlapping changes (SecurityModal is dismissible while a save
   *  is in flight — closing it unmounts that instance; reopening starts a
   *  genuinely independent second request before the first has resolved)
   *  could previously have the generation guard keep the FIRST-ARRIVING
   *  response even when the SECOND-ARRIVING one was actually the
   *  server's real, current winner — leaving the browser holding a token
   *  that 401s on its very next request. Serializing at the source (never
   *  let a second change start while one is already in flight) removes
   *  the ambiguity entirely, rather than trying to guess the right
   *  winner after the fact from information the browser doesn't have.
   *
   *  Also internally records the generation current at this exact call —
   *  read by the auth:unauthorized handler below to tell "a 401 that
   *  belongs to THIS still-outstanding change" apart from "a 401 for an
   *  entirely later session that merely happens to start before this
   *  change's own PATCH promise settles" (that promise is not cancelled
   *  by an intervening logout/login — it is not tied to any component's
   *  lifecycle). See that handler's own comment for why a plain boolean
   *  was not narrow enough for this. */
  beginPasswordChange: () => boolean
  /** Releases the slot `beginPasswordChange()` reserved. Must be called
   *  exactly once per successful `beginPasswordChange()`, whether the
   *  request that followed it succeeded, failed, or threw. */
  endPasswordChange: () => void
}

const Ctx = createContext<AuthCtx>(null!)
export const useAuth = () => useContext(Ctx)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const [token, setTokenState] = useState<string | null>(() => localStorage.getItem('token'))
  // Bumped by every write below (login/completeTotp/logout/setToken) — see
  // setToken's own docstring for the race this exists to close. A ref, not
  // state: nothing needs to re-render when this changes on its own, only
  // when read back later to decide whether an async caller's own write is
  // still current.
  const authGeneration = useRef(0)
  const getAuthGeneration = () => authGeneration.current
  // See beginPasswordChange's own docstring for why this exists alongside
  // (not instead of) the generation guard above: it serializes overlapping
  // password-change REQUESTS at the source, since picking a winner after
  // the fact from arrival order alone can pick the wrong one.
  //
  // Stores the generation that was current WHEN this password change
  // started (null when none is in flight), not just a boolean — see the
  // auth:unauthorized handler below for why: passwordChangeInFlight used
  // to be a plain flag, but a flag has no way to tell "this password
  // change" apart from "some LATER, unrelated session" once a logout and
  // a fresh login happen while the original PATCH is still in flight (its
  // own promise is not cancelled by either — it is not tied to any
  // component's lifecycle at all). Storing the generation lets that
  // handler compare against the specific rotation this change belongs to,
  // rather than merely whether *some* change is outstanding.
  const passwordChangeGeneration = useRef<number | null>(null)
  const beginPasswordChange = () => {
    if (passwordChangeGeneration.current !== null) return false
    passwordChangeGeneration.current = authGeneration.current
    return true
  }
  const endPasswordChange = () => {
    passwordChangeGeneration.current = null
  }

  useEffect(() => {
    // Mount-only: login/completeTotp/setToken each already know the token
    // they just installed and update `user`/`token` state directly, so this
    // must not re-run on every `token` change — doing so would fire a
    // redundant second api.auth.me() race right alongside the one login/
    // completeTotp already issue themselves.
    // eslint-disable-next-line react-hooks/set-state-in-effect -- early-return when no token; synchronous setState is intentional here
    if (!token) { setLoading(false); return }
    api.auth.me().then(setUser).catch(() => { localStorage.removeItem('token'); setTokenState(null) }).finally(() => setLoading(false))
    // eslint-disable-next-line react-hooks/exhaustive-deps -- deliberately mount-only, see comment above
  }, [])

  useEffect(() => {
    // The event carries the token the failed request actually used —
    // compare against localStorage (the source of truth for "current"; it
    // is what api.ts's own getToken() reads for the NEXT request) rather
    // than the `token` state closed over here, which could itself be
    // stale inside this effect between renders. A self-password-change
    // (setToken) can install a replacement token while an older request
    // — issued before that change, with the old token — is still in
    // flight; that request's 401 is real (its token's epoch was bumped
    // server-side) but says nothing about the NEW token just installed.
    // Only clear auth when the failed request's token is still the one
    // actually in use — an unauthorized response for a token that has
    // already been superseded is stale news, not a reason to log out.
    const handler = (event: Event) => {
      const failedToken = (event as CustomEvent<{ token: string | null }>).detail?.token
      if (failedToken !== localStorage.getItem('token')) return
      // Bumped alongside the clear below — every OTHER write to this
      // provider does the same (see authGeneration's own docstring above)
      // — EXCEPT when this 401 belongs to a self-password-change that is
      // STILL the most recent write (passwordChangeGeneration, above:
      // the generation that was current when that change's PATCH started,
      // not yet superseded by anything else). Without bumping in the
      // general case, a login()/completeTotp() call whose own me() is
      // still in flight when this handler clears the session captures no
      // signal that anything changed: its generation check at the end of
      // that call still passes (nothing bumped it), so its delayed
      // setUser(freshUser) silently repopulates `user` right after this
      // handler just cleared it — Guard (App.tsx) checks `user`, not
      // `token`, so it would treat the client as authenticated despite
      // localStorage holding no token at all.
      //
      // But bumping unconditionally reopens a DIFFERENT, pre-existing
      // race this same handler's own docstring above already relies on
      // being closed the other way: SecurityModal captures its generation
      // via getAuthGeneration() BEFORE its PATCH starts, using the
      // pre-change token. set_password bumps token_epoch as soon as the
      // change commits server-side, strictly before the PATCH response
      // (carrying the replacement token) reaches the browser — so an
      // unrelated request already in flight, still using that now-stale
      // token, can 401 in that exact window. Bumping the generation here
      // for that 401 would make the still-pending setToken call's own
      // captured generation stale by the time its response arrives,
      // rejecting a perfectly valid replacement token and leaving the
      // user logged out after a SUCCESSFUL password change.
      //
      // A plain "is some change in flight" flag is not narrow enough: the
      // PATCH promise is not cancelled by a logout or a fresh login (it is
      // not tied to any component's lifecycle at all), so a flag would
      // still read "in flight" long after an entirely UNRELATED session
      // has started — incorrectly suppressing the bump for a 401 that
      // belongs to that NEW login's own me() race, reopening the exact
      // resurrection bug the bump exists to close. Comparing against the
      // generation captured when the change began avoids this: if
      // anything else has legitimately written since (logout, a fresh
      // login, another setToken), authGeneration.current has already
      // moved past passwordChangeGeneration.current, and the exception no
      // longer applies — the original PATCH's own eventual setToken call
      // would already be rejected by ITS generation check by then anyway,
      // so there is nothing left to protect by skipping the bump here.
      const inFlight = passwordChangeGeneration.current
      const isForThatSameStillCurrentChange = inFlight !== null && inFlight === authGeneration.current
      if (!isForThatSameStillCurrentChange) authGeneration.current += 1
      localStorage.removeItem('token'); setTokenState(null); setUser(null)
    }
    window.addEventListener('auth:unauthorized', handler)
    return () => window.removeEventListener('auth:unauthorized', handler)
  }, [])

  const login = async (email: string, password: string): Promise<TotpChallenge | null> => {
    const resp = await api.auth.login(email, password)
    if ('totp_required' in resp) {
      return resp as TotpChallenge
    }
    // Bumped BEFORE the trailing api.auth.me() below, not after — see
    // setToken's own docstring for why the generation exists at all.
    // Publishing the new token to localStorage/state first and only
    // incrementing once me() has *also* resolved left a window, for the
    // whole duration of that await, where the generation was still
    // whatever it was before this login — an older, still-in-flight
    // setToken call (e.g. from a password change under the PREVIOUS
    // session) captured that same value and could pass this function's
    // own check, overwriting the token this call just published with a
    // stale one, moments before this call's own setUser below installed
    // the newly-logged-in user on top of it — a live but mismatched
    // user/token pair. Incrementing here closes that window: any
    // setToken call captured under the old generation is rejected from
    // this point on, regardless of how long the me() call below takes.
    const generation = ++authGeneration.current
    localStorage.setItem('token', resp.access_token)
    setTokenState(resp.access_token)
    const freshUser = await api.auth.me()
    // Guards the SAME class of window from the other direction: if
    // something else (a fresh login/logout, or another setToken this
    // login's own bump didn't need to block) advances the generation
    // again while this me() call is still in flight, that later write
    // already reflects the true current state and this call's own
    // (now-stale) result must not overwrite it.
    if (generation === authGeneration.current) setUser(freshUser)
    return null
  }

  const completeTotp = async (sessionToken: string, code: string): Promise<void> => {
    const { access_token } = await api.auth.totpVerify(sessionToken, code)
    // Same reasoning as login() above — see its own comment for the
    // window this closes.
    const generation = ++authGeneration.current
    localStorage.setItem('token', access_token)
    setTokenState(access_token)
    const freshUser = await api.auth.me()
    if (generation === authGeneration.current) setUser(freshUser)
  }

  const logout = () => {
    localStorage.removeItem('token')
    setTokenState(null)
    setUser(null)
    authGeneration.current += 1
  }

  const setToken = (accessToken: string, newUser: User, expectedGeneration: number) => {
    // Silently ignored if superseded — see this function's own docstring
    // for the race this guards: an older SecurityModal save (or ANY other
    // write to this provider — a logout, a fresh login) that landed while
    // this call's request was still in flight means the caller's result
    // is no longer the truth to install, since something newer already is.
    if (expectedGeneration !== authGeneration.current) return
    authGeneration.current += 1
    localStorage.setItem('token', accessToken)
    setTokenState(accessToken)
    setUser(newUser)
  }

  return (
    <Ctx.Provider value={{
      user, loading, token, login, completeTotp, logout, setToken, getAuthGeneration,
      beginPasswordChange, endPasswordChange,
    }}>
      {children}
    </Ctx.Provider>
  )
}
