import { useState, useEffect, useRef, FormEvent } from 'react'
import { useNavigate, useLocation } from 'react-router'
import { Shield } from 'lucide-react'
import { Button, Input } from '@/components/ui'
import { api } from '@/lib/api'
import { codePointLength, MAX_PASSWORD_BYTES, utf8ByteLength } from '@/lib/text'

const MIN_PASSWORD_LENGTH = 12

/**
 * Read the reset token from the URL fragment.
 *
 * The token lives in the fragment rather than the query string because a
 * fragment is never sent to the server: it stays out of reverse-proxy and
 * access logs, and out of `Referer` headers.
 */
function readToken(hash: string): string {
  return new URLSearchParams(hash.replace(/^#/, '')).get('token') ?? ''
}

export default function ResetPassword() {
  const navigate = useNavigate()
  const location = useLocation()
  const token = readToken(location.hash)

  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [done, setDone] = useState(false)
  const [enabled, setEnabled] = useState<boolean | null>(null)
  const passwordRef = useRef<HTMLInputElement>(null)

  // Only used to explain a *missing* token. An already-issued link stays
  // usable even if the feature has since been switched off — the backend
  // retires outstanding tokens when that happens rather than refusing them,
  // so a link that still exists is a link that still works. Hiding the form
  // here would strand exactly the people who cannot recover any other way:
  // an admin-reset victim whose password is already invalidated, or a new
  // account whose only credential is this link.
  useEffect(() => {
    api.auth.passwordResetConfig()
      .then(cfg => setEnabled(cfg.self_service_enabled))
      .catch(() => setEnabled(false))
  }, [])

  // Focus the password field once the form is actually rendered. Uses a ref
  // rather than autoFocus, which jsx-a11y forbids — and the field does not
  // exist on first paint anyway, since the config fetch decides whether the
  // form renders at all.
  useEffect(() => {
    if (token) passwordRef.current?.focus()
  }, [token])

  // Strip the token from the address bar once it has been read into state.
  // The fragment already keeps it out of server logs and Referer headers,
  // but it would otherwise sit in browser history and on screen, where a
  // shoulder-surfer or a shared machine could recover a link that stays
  // valid for up to a week. replaceState leaves no new history entry.
  //
  // Passing `window.history.state`, not `null`, as the state argument.
  // BrowserRouter's own history implementation stores its bookkeeping
  // there — `{ usr, key, idx, masked? }`, where `idx` is the router's
  // position in the history stack — and reads it back via
  // `(window.history.state || { idx: null }).idx` on every browser
  // back/forward event to compute how far the user navigated. Passing
  // `null` here discards that object outright, so the very next pop sets
  // the router's internally tracked index to `null`: confirmed directly by
  // replaying react-router's own getIndex()/handlePop() logic against a
  // `replaceState(null, ...)` call, which desynchronizes the tracked index
  // from the real history position and would break useBlocker and other
  // history-index-dependent behaviour from that point on. Re-supplying the
  // current state object leaves the router's bookkeeping untouched while
  // still replacing the URL, which is the only thing this effect is
  // actually trying to change.
  useEffect(() => {
    if (!token || !window.location.hash) return
    window.history.replaceState(
      window.history.state, '', `${window.location.pathname}${window.location.search}`
    )
  }, [token])

  const tooShort = password.length > 0 && codePointLength(password) < MIN_PASSWORD_LENGTH
  // Mirrors ResetPasswordRequest's own bcrypt-byte-limit validator
  // (schemas/__init__.py's _reject_password_over_bcrypt_limit): bcrypt
  // hashes only the first 72 *bytes*, and a password that looks short by
  // character count can still exceed that — 40 "é" characters is 40 code
  // points (well past MIN_PASSWORD_LENGTH) but 80 UTF-8 bytes, so it passed
  // this form and was rejected by the backend with no explanation shown
  // here.
  const tooLong = utf8ByteLength(password) > MAX_PASSWORD_BYTES
  const mismatch = confirm.length > 0 && password !== confirm
  const submittable =
    codePointLength(password) >= MIN_PASSWORD_LENGTH && !tooLong &&
    password === confirm && !loading

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setLoading(true); setError('')
    try {
      await api.auth.resetPassword(token, password)
      setDone(true)
    } catch (err: any) {
      setError(err.message || 'Could not reset your password')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="bg-card border border-border rounded-[var(--radius-lg)] p-12 w-[440px]">
        <div className="flex flex-col items-center text-center mb-8">
          <div className="w-12 h-12 rounded-full bg-brand-tint border border-brand/35 flex items-center justify-center mb-4">
            <Shield size={22} className="text-brand" />
          </div>
          <h1 className="text-[18px] font-semibold tracking-tight">PA Central</h1>
          <p className="text-muted-foreground text-[13px] mt-1.5">
            {done ? 'Password updated' : 'Choose a new password'}
          </p>
        </div>

        {!token && (
          <Notice>
            {enabled === false
              ? 'This reset link is missing its token, and self-service password reset is not enabled. Contact an administrator to have your password reset.'
              : 'This reset link is missing its token. Request a new link from the sign-in page.'}
          </Notice>
        )}

        {token && !done && (
          <form onSubmit={submit} className="flex flex-col gap-4">
            <p className="text-[13px] text-muted-foreground leading-relaxed">
              Pick a new password of at least {MIN_PASSWORD_LENGTH} characters.
              This link can only be used once.
            </p>
            <Input label="New password" type="password" value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="••••••••••••" required ref={passwordRef} />
            <Input label="Confirm new password" type="password" value={confirm}
              onChange={e => setConfirm(e.target.value)}
              placeholder="••••••••••••" required />
            {tooShort && <HintBox>Must be at least {MIN_PASSWORD_LENGTH} characters.</HintBox>}
            {tooLong && (
              <HintBox>
                Too long: at most {MAX_PASSWORD_BYTES} bytes once encoded —
                non-ASCII characters (accents, emoji) can use more than one
                byte each.
              </HintBox>
            )}
            {mismatch && <HintBox>The two passwords don't match.</HintBox>}
            {error && <ErrorBox>{error}</ErrorBox>}
            <Button type="submit" variant="primary" disabled={!submittable}
              className="w-full justify-center mt-1">
              {loading ? 'Saving…' : 'Set new password'}
            </Button>
          </form>
        )}

        {done && (
          <div className="flex flex-col gap-4">
            <p className="text-[13px] text-muted-foreground leading-relaxed">
              Your password has been updated. Sign in with your new password —
              two-factor authentication is unchanged.
            </p>
            <Button variant="primary" className="w-full justify-center"
              onClick={() => navigate('/login')}>
              Go to sign in
            </Button>
          </div>
        )}

        {!token && (
          <Button variant="secondary" className="w-full justify-center mt-4"
            onClick={() => navigate('/login')}>
            Back to sign in
          </Button>
        )}
      </div>
    </div>
  )
}

function ErrorBox({ children }: { children: string }) {
  return (
    <div className="bg-status-fail/10 border border-status-fail/30 text-status-fail-text px-3 py-2 rounded-[var(--radius-sm)] text-xs">
      {children}
    </div>
  )
}

function HintBox({ children }: { children: React.ReactNode }) {
  return <span className="text-muted-foreground text-xs">{children}</span>
}

function Notice({ children }: { children: React.ReactNode }) {
  return (
    <p className="text-[13px] text-muted-foreground leading-relaxed">{children}</p>
  )
}
