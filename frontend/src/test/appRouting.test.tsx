/**
 * App route table, auth guards, and redirects.
 *
 * This is the client-side authorization boundary: `Guard` gates every route
 * behind a session, and `AdminGuard` gates four of them behind the admin role.
 * Neither had any coverage.
 *
 * Page components are stubbed so these assert *routing decisions* rather than
 * page rendering — the real pages each fetch on mount and are covered by their
 * own suites. `App` hardcodes BrowserRouter, so the URL is driven through
 * window.history, which exercises the real router rather than swapping in
 * MemoryRouter.
 */
import { render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { vi, beforeEach, afterEach, describe, it, expect } from 'vitest'
import type { User } from '@/lib/api'

// ── Module mocks (hoisted) ────────────────────────────────────────────────────

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
  // AuthProvider must still render children for the route tree to mount.
  AuthProvider: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

// Stub every page: routing is under test, not page content. The factories are
// inlined rather than built by a helper — vi.mock is hoisted above any local
// declaration, so referencing one here would throw at import time.
vi.mock('@/pages/Login', () => ({ default: () => <div>page:login</div> }))
vi.mock('@/pages/Dashboard', () => ({ default: () => <div>page:dashboard</div> }))
vi.mock('@/pages/Hosts', () => ({ default: () => <div>page:hosts</div> }))
vi.mock('@/pages/HostDetail', () => ({ default: () => <div>page:host-detail</div> }))
vi.mock('@/pages/Alerts', () => ({ default: () => <div>page:alerts</div> }))
vi.mock('@/pages/Cooldown', () => ({ default: () => <div>page:cooldown</div> }))
vi.mock('@/pages/Configs', () => ({ default: () => <div>page:configs</div> }))
vi.mock('@/pages/ApiKeys', () => ({ default: () => <div>page:api-keys</div> }))
vi.mock('@/pages/Users', () => ({ default: () => <div>page:users</div> }))
vi.mock('@/pages/RepoScans', () => ({ default: () => <div>page:repo-scans</div> }))
vi.mock('@/pages/SystemSettings', () => ({ default: () => <div>page:settings</div> }))
// Scans is a named export, not a default.
vi.mock('@/pages/Scans', () => ({ Scans: () => <div>page:scans</div> }))

import { useAuth } from '@/hooks/useAuth'
import App from '@/App'

// ── Helpers ───────────────────────────────────────────────────────────────────

const ADMIN: User = {
  id: 1, email: 'admin@example.com', display_name: 'Admin',
  role: 'admin', is_active: true, totp_enabled: false, created_at: '2024-01-01T00:00:00Z',
}
const VIEWER: User = { ...ADMIN, id: 2, email: 'v@example.com', display_name: 'Viewer', role: 'viewer' }

function signedIn(user: User | null, { loading = false } = {}) {
  vi.mocked(useAuth).mockReturnValue({
    user, loading,
    login: vi.fn(), completeTotp: vi.fn(), logout: vi.fn(),
  })
}

function renderAt(path: string) {
  window.history.pushState({}, '', path)
  return render(<App />)
}

/** Resolve once the router has settled, then report the rendered page stub. */
async function landedOn(): Promise<string> {
  const el = await screen.findByText(/^page:/)
  return el.textContent!.replace('page:', '')
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('App routing — unauthenticated', () => {
  beforeEach(() => { vi.clearAllMocks(); signedIn(null) })
  afterEach(() => { vi.restoreAllMocks() })

  it.each([
    '/', '/hosts', '/hosts/7', '/alerts', '/scans', '/cooldown',
    '/configs', '/api-keys', '/users', '/repo-scans', '/settings',
  ])('redirects %s to /login', async (path) => {
    renderAt(path)
    expect(await landedOn()).toBe('login')
    await waitFor(() => expect(window.location.pathname).toBe('/login'))
  })

  it('renders /login without redirecting', async () => {
    renderAt('/login')
    expect(await landedOn()).toBe('login')
    expect(window.location.pathname).toBe('/login')
  })

  it('shows nothing while the session is still loading', () => {
    signedIn(null, { loading: true })
    const { container } = renderAt('/hosts')
    // Guard renders a placeholder rather than bouncing to /login prematurely —
    // otherwise a page refresh would flash the login screen for every user.
    expect(screen.queryByText(/^page:/)).not.toBeInTheDocument()
    expect(container.querySelector('.auth-loading')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/hosts')
  })
})

describe('App routing — signed in as a non-admin', () => {
  beforeEach(() => { vi.clearAllMocks(); signedIn(VIEWER) })
  afterEach(() => { vi.restoreAllMocks() })

  it.each([
    ['/', 'dashboard'],
    ['/hosts', 'hosts'],
    ['/hosts/7', 'host-detail'],
    ['/alerts', 'alerts'],
    ['/cooldown', 'cooldown'],
    ['/configs', 'configs'],
    ['/api-keys', 'api-keys'],
  ])('renders %s', async (path, expected) => {
    renderAt(path)
    expect(await landedOn()).toBe(expected)
  })

  // The admin-only half of the route table. A regression here would expose
  // admin pages to every signed-in user.
  it.each(['/scans', '/users', '/repo-scans', '/settings'])(
    'redirects admin-only %s to the dashboard',
    async (path) => {
      renderAt(path)
      expect(await landedOn()).toBe('dashboard')
      await waitFor(() => expect(window.location.pathname).toBe('/'))
    },
  )
})

describe('App routing — signed in as an admin', () => {
  beforeEach(() => { vi.clearAllMocks(); signedIn(ADMIN) })
  afterEach(() => { vi.restoreAllMocks() })

  it.each([
    ['/scans', 'scans'],
    ['/users', 'users'],
    ['/repo-scans', 'repo-scans'],
    ['/settings', 'settings'],
  ])('renders admin-only %s', async (path, expected) => {
    renderAt(path)
    expect(await landedOn()).toBe(expected)
  })
})

describe('App routing — unmatched paths', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => { vi.restoreAllMocks() })

  it('sends an unknown path to the dashboard when signed in', async () => {
    signedIn(ADMIN)
    renderAt('/no-such-page')
    expect(await landedOn()).toBe('dashboard')
    await waitFor(() => expect(window.location.pathname).toBe('/'))
  })

  it('sends an unknown path to /login when signed out', async () => {
    signedIn(null)
    renderAt('/no-such-page')
    // Catch-all rewrites to "/", which the Guard then bounces to /login.
    expect(await landedOn()).toBe('login')
    await waitFor(() => expect(window.location.pathname).toBe('/login'))
  })
})
