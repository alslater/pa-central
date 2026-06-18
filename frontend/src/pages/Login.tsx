import { useState, useEffect, useRef, FormEvent } from 'react'
import { QRCodeSVG } from 'qrcode.react'
import { useNavigate } from 'react-router-dom'
import { Shield, Eye, EyeOff } from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { Button, Input } from '@/components/ui'
import { TotpChallenge } from '@/lib/api'

type Step = 'credentials' | 'totp-setup' | 'totp-verify'

export default function Login() {
  const { login, completeTotp } = useAuth()
  const navigate = useNavigate()

  const [step, setStep] = useState<Step>('credentials')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [challenge, setChallenge] = useState<TotpChallenge | null>(null)
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [secretVisible, setSecretVisible] = useState(false)
  const codeRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (step === 'totp-setup' || step === 'totp-verify') {
      codeRef.current?.focus()
    }
  }, [step])

  const submitCredentials = async (e: FormEvent) => {
    e.preventDefault()
    setLoading(true); setError('')
    try {
      const ch = await login(email, password)
      if (!ch) { navigate('/'); return }
      setChallenge(ch)
      setStep(ch.totp_setup_required ? 'totp-setup' : 'totp-verify')
    } catch (err: any) {
      setError(err.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  const submitTotp = async (e: FormEvent) => {
    e.preventDefault()
    if (!challenge) return
    setLoading(true); setError('')
    try {
      await completeTotp(challenge.totp_session_token, code)
      navigate('/')
    } catch (err: any) {
      setError(err.message || 'Invalid code')
      setCode('')
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
            {step === 'credentials' && 'package-alert fleet management'}
            {step === 'totp-setup' && 'Set up two-factor authentication'}
            {step === 'totp-verify' && 'Two-factor authentication'}
          </p>
        </div>

        {step === 'credentials' && (
          <form onSubmit={submitCredentials} className="flex flex-col gap-4">
            <Input label="Email" type="email" value={email}
              onChange={e => setEmail(e.target.value)} placeholder="admin@localhost" required />
            <Input label="Password" type="password" value={password}
              onChange={e => setPassword(e.target.value)} placeholder="••••••••••••" required />
            {error && <ErrorBox>{error}</ErrorBox>}
            <Button type="submit" variant="primary" disabled={loading} className="w-full justify-center mt-2">
              {loading ? 'Signing in…' : 'Sign in'}
            </Button>
          </form>
        )}

        {step === 'totp-setup' && challenge?.totp_uri && (
          <form onSubmit={submitTotp} className="flex flex-col gap-4">
            <p className="text-[13px] text-muted-foreground leading-relaxed">
              Your account requires two-factor authentication. Scan the QR code below with Google Authenticator or a compatible app, then enter the 6-digit code to complete setup.
            </p>
            <QrCode uri={challenge.totp_uri} />
            <div className="flex items-center justify-center gap-1.5">
              <span className="text-[11px] text-muted-foreground font-mono break-all">
                {secretVisible ? extractSecret(challenge.totp_uri) : '••••••••••••••••••••••••••••••••'}
              </span>
              <button type="button" onClick={() => setSecretVisible(v => !v)}
                className="bg-transparent border-none cursor-pointer text-muted-foreground p-0.5 flex"
                title={secretVisible ? 'Hide secret' : 'Reveal secret for manual entry'}
                aria-label={secretVisible ? 'Hide secret' : 'Reveal secret for manual entry'}>
                {secretVisible ? <EyeOff size={13} /> : <Eye size={13} />}
              </button>
            </div>
            <Input label="6-digit code" type="text" inputMode="numeric" pattern="[0-9]{6}"
              maxLength={6} value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ''))}
              placeholder="000000" required ref={codeRef} />
            {error && <ErrorBox>{error}</ErrorBox>}
            <Button type="submit" variant="primary" disabled={loading || code.length !== 6} className="w-full justify-center">
              {loading ? 'Verifying…' : 'Activate & sign in'}
            </Button>
          </form>
        )}

        {step === 'totp-verify' && (
          <form onSubmit={submitTotp} className="flex flex-col gap-3.5">
            <p className="text-[13px] text-muted-foreground leading-relaxed">
              Enter the 6-digit code from your authenticator app.
            </p>
            <Input label="Authentication code" type="text" inputMode="numeric" pattern="[0-9]{6}"
              maxLength={6} value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ''))}
              placeholder="000000" required ref={codeRef} />
            {error && <ErrorBox>{error}</ErrorBox>}
            <Button type="submit" variant="primary" disabled={loading || code.length !== 6} className="w-full justify-center mt-1">
              {loading ? 'Verifying…' : 'Verify'}
            </Button>
            <button type="button" onClick={() => { setStep('credentials'); setError(''); setCode('') }}
              className="bg-transparent border-none cursor-pointer text-muted-foreground text-xs mt-1">
              ← Back to sign in
            </button>
          </form>
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

function extractSecret(uri: string): string {
  try {
    const secret = new URL(uri).searchParams.get('secret')
    return secret ? `Secret: ${secret}` : ''
  } catch { return '' }
}

function QrCode({ uri }: { uri: string }) {
  return (
    <div className="text-center">
      <QRCodeSVG
        value={uri}
        size={180}
        className="rounded-lg border border-border"
      />
    </div>
  )
}
