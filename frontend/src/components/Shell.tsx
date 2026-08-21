import { ReactNode, useEffect, useState, useRef } from 'react'
import { NavLink, useNavigate } from 'react-router'
import {
  LayoutDashboard, Server, Bell, ScanSearch, Settings2,
  ShieldCheck, Key, Users, LogOut, Shield, GitBranch, Sliders,
  Sun, Moon, Monitor, ShieldAlert, TriangleAlert,
} from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import { Modal, Input, Button, useToast } from '@/components/ui'
import { useTheme, ThemeMode } from '@/hooks/useTheme'

const NAV = [
  { to: '/',          label: 'Dashboard',   icon: LayoutDashboard },
  { to: '/hosts',     label: 'Hosts',       icon: Server },
  { to: '/alerts',    label: 'Alerts',      icon: Bell },
  { to: '/scans',     label: 'Scans',       icon: ScanSearch },
  { to: '/cooldown',  label: 'Cooldown',    icon: ShieldCheck },
  { to: '/configs',   label: 'Config',      icon: Settings2 },
  { to: '/api-keys',  label: 'API Keys',    icon: Key },
  { to: '/repo-scans', label: 'Repo Scans', icon: GitBranch, adminOnly: true },
  { to: '/vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert, adminOnly: true },
  { to: '/risks',     label: 'Risks',       icon: TriangleAlert, adminOnly: true },
  { to: '/users',     label: 'Users',       icon: Users, adminOnly: true },
  { to: '/settings',  label: 'Settings',    icon: Sliders, adminOnly: true },
]


function useLiveAlerts() {
  const [count, setCount] = useState(0)
  const abortRef = useRef<AbortController | null>(null)

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) return

    const controller = new AbortController()
    abortRef.current = controller

    ;(async () => {
      try {
        const res = await fetch('/api/alerts/stream', {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
        })
        if (!res.ok || !res.body) return
        const reader = res.body.getReader()
        const decoder = new TextDecoder()
        let buf = ''
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          buf += decoder.decode(value, { stream: true })
          const lines = buf.split('\n')
          buf = lines.pop() ?? ''
          for (const line of lines) {
            if (!line.startsWith('data:')) continue
            try {
              const data = JSON.parse(line.slice(5).trim())
              if (data.type === 'connected') continue
              setCount(n => n + 1)
            } catch { /* ignore malformed SSE data */ }
          }
        }
      } catch {
        // AbortError on unmount — ignore
      }
    })()

    return () => { controller.abort() }
  }, [])

  return { count, clear: () => setCount(0) }
}

function SecurityModal({ userId, totpEnabled: initialTotpEnabled, onClose }: {
  userId: number
  totpEnabled: boolean
  onClose: () => void
}) {
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [pwSaving, setPwSaving] = useState(false)
  const [pwError, setPwError] = useState<string | null>(null)

  const [totpEnabled, setTotpEnabled] = useState(initialTotpEnabled)
  const [totpCode, setTotpCode] = useState('')
  const [totpSaving, setTotpSaving] = useState(false)
  const [totpError, setTotpError] = useState<string | null>(null)

  const { show } = useToast()

  const savePassword = async () => {
    if (next.length < 12) { setPwError('Password must be at least 12 characters'); return }
    const complexity = [/[A-Z]/, /[a-z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(r => r.test(next)).length
    if (complexity < 3) { setPwError('Password must contain at least 3 of: uppercase, lowercase, digits, symbols'); return }
    if (next !== confirm) { setPwError('Passwords do not match'); return }
    setPwSaving(true); setPwError(null)
    try {
      await api.users.update(userId, { password: next } as any)
      show('Password changed')
      setNext(''); setConfirm('')
    } catch (e: any) { setPwError(e.message) }
    finally { setPwSaving(false) }
  }

  const disableTotp = async () => {
    setTotpSaving(true); setTotpError(null)
    try {
      await api.auth.totpDisable(totpCode)
      show('Two-factor authentication disabled')
      setTotpEnabled(false); setTotpCode('')
    } catch (e: any) { setTotpError(e.message) }
    finally { setTotpSaving(false) }
  }

  return (
    <Modal title="Account security" onClose={onClose}>
      <div className="flex flex-col min-w-[340px]">

        <div className="text-style-caption mb-2.5">Change password</div>
        <div className="flex flex-col gap-2.5">
          <Input label="New password" type="password" value={next} onChange={e => setNext(e.target.value)} />
          <Input label="Confirm new password" type="password" value={confirm} onChange={e => setConfirm(e.target.value)} />
          {pwError && <div className="text-xs text-destructive">{pwError}</div>}
          <div className="flex justify-end">
            <Button variant="primary" onClick={savePassword} disabled={!next || !confirm || pwSaving}>
              {pwSaving ? 'Saving…' : 'Change password'}
            </Button>
          </div>
        </div>

        <div className="pt-4 mt-4 border-t border-border">
          <div className="text-style-caption mb-2.5">Two-factor authentication</div>
          {totpEnabled ? (
            <div className="flex flex-col gap-2.5">
              <div className="text-[13px] text-muted-foreground">
                TOTP is <strong>enabled</strong>. Enter your current authenticator code to disable it.
              </div>
              <Input label="Authenticator code" type="text" inputMode="numeric"
                maxLength={6} value={totpCode}
                onChange={e => setTotpCode(e.target.value.replace(/\D/g, ''))}
                placeholder="000000" />
              {totpError && <div className="text-xs text-destructive">{totpError}</div>}
              <div className="flex justify-end">
                <Button variant="danger" onClick={disableTotp} disabled={totpCode.length !== 6 || totpSaving}>
                  {totpSaving ? 'Disabling…' : 'Disable 2FA'}
                </Button>
              </div>
            </div>
          ) : (
            <div className="text-[13px] text-muted-foreground">
              TOTP is <strong>disabled</strong>. It will be set up automatically on your next login.
            </div>
          )}
        </div>

        <div className="flex justify-end mt-5">
          <Button variant="secondary" onClick={onClose}>Close</Button>
        </div>
      </div>
    </Modal>
  )
}

function ThemeToggle({ mode, onCycle }: { mode: ThemeMode; onCycle: () => void }) {
  const Icon = THEME_ICON[mode]
  return (
    <button type="button" onClick={onCycle} title={`Theme: ${THEME_LABEL[mode]} (click to cycle)`} aria-label={`Theme: ${THEME_LABEL[mode]} (click to cycle)`}
      className="bg-transparent border-none cursor-pointer text-sidebar-muted p-0.5">
      <Icon size={13} />
    </button>
  )
}

const THEME_CYCLE: ThemeMode[] = ['dark', 'light', 'system']
const THEME_ICON: Record<ThemeMode, typeof Sun> = { dark: Moon, light: Sun, system: Monitor }
const THEME_LABEL: Record<ThemeMode, string> = { dark: 'Dark', light: 'Light', system: 'System' }

export function Shell({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const { count, clear } = useLiveAlerts()
  const [showSecurity, setShowSecurity] = useState(false)
  const { mode, setMode } = useTheme()

  const cycleTheme = () => {
    const next = THEME_CYCLE[(THEME_CYCLE.indexOf(mode) + 1) % THEME_CYCLE.length]
    setMode(next)
  }

  const handleLogout = () => { logout(); navigate('/login') }

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="w-[220px] shrink-0 bg-sidebar border-r border-sidebar-border flex flex-col overflow-hidden">
        {/* Logo */}
        <div className="px-4 pt-6 pb-5 border-b border-sidebar-border">
          <div className="flex items-center gap-2">
            <Shield size={18} className="text-brand" />
            <span className="font-semibold text-[17px] tracking-tight text-sidebar-foreground">
              PA Central
            </span>
          </div>
          <div className="text-xs text-sidebar-muted mt-0.5 pl-[26px]">
            package-alert management
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 p-2 overflow-y-auto">
          {NAV.filter(n => !n.adminOnly || user?.role === 'admin').map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} end={to === '/'}
              onClick={to === '/alerts' ? clear : undefined}
              className={({ isActive }) =>
                `flex items-center gap-2.5 px-2.5 py-[7px] rounded-[var(--radius-sm)] text-[13px] font-medium mb-px transition-[background,color] duration-[120ms] ${
                  isActive
                    ? 'text-brand bg-sidebar-active'
                    : 'text-sidebar-foreground bg-transparent'
                }`
              }>
              <Icon size={14} />
              <span>{label}</span>
              {to === '/alerts' && count > 0 && (
                <span className="bg-status-fail text-on-accent rounded-[10px] text-[10px] font-bold px-1.5 py-px leading-snug">
                  {count}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        {/* User */}
        <div className="px-4 py-3 border-t border-sidebar-border flex items-center gap-2">
          <div className="w-7 h-7 rounded-full bg-brand-tint border border-brand/35 flex items-center justify-center text-[11px] font-semibold text-brand shrink-0">
            {user?.display_name?.[0]?.toUpperCase()}
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-xs font-medium overflow-hidden text-ellipsis whitespace-nowrap text-sidebar-foreground">
              {user?.display_name}
            </div>
            <div className="text-style-caption text-sidebar-muted">
              {user?.role}
            </div>
          </div>
          <button type="button" onClick={() => setShowSecurity(true)} title="Account security" aria-label="Account security"
            className="bg-transparent border-none cursor-pointer text-sidebar-muted p-0.5">
            <Key size={13} />
          </button>
          <ThemeToggle mode={mode} onCycle={cycleTheme} />
          <button type="button" onClick={handleLogout} title="Sign out" aria-label="Sign out"
            className="bg-transparent border-none cursor-pointer text-sidebar-muted p-0.5">
            <LogOut size={13} />
          </button>
        </div>
      </aside>
      {showSecurity && user && (
        <SecurityModal userId={user.id} totpEnabled={user.totp_enabled} onClose={() => setShowSecurity(false)} />
      )}

      {/* Main */}
      <main className="flex-1 overflow-auto flex flex-col">
        {children}
      </main>
    </div>
  )
}

export function PageHeader({ title, subtitle, action }: {
  title: string; subtitle?: string; action?: ReactNode
}) {
  return (
    <div className="px-7 pt-6 pb-5 border-b border-border flex justify-between items-start shrink-0">
      <div>
        <h1 className="text-[17px] font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="text-muted-foreground text-xs mt-0.5">{subtitle}</p>}
      </div>
      {action && <div>{action}</div>}
    </div>
  )
}
