/**
 * Login.tsx's redirect-away-when-authenticated effect, with the router
 * actually mounted — not stubbed the way appRouting.test.tsx stubs every
 * page (that file asserts routing DECISIONS; this one needs the real
 * Login component and the real Guard/Navigate interaction, since the bug
 * this covers is specifically about what's left on screen after a route
 * change nothing else notices).
 *
 * The scenario: Guard (App.tsx) redirects to /login purely on `user`
 * being falsy, with no symmetric redirect away once `user` becomes
 * truthy again. In the stale-401-first ordering of the password-change
 * race (see useAuthSetToken.test.tsx's own race tests), Guard can render
 * <Navigate to="/login"> BEFORE the password-change response — and its
 * setToken(token, user) call — actually arrives. That call still runs (it
 * operates on AuthProvider state, which survives the route change and the
 * unmount of whatever page/modal triggered it) and correctly restores
 * `user`, but without Login's own effect, nothing ever notices and
 * navigates back — the login form stays on screen despite a valid session.
 */
import { render, screen, act } from '@testing-library/react'
import { MemoryRouter, Routes, Route, Navigate } from 'react-router'
import { vi, beforeEach, afterEach, describe, it, expect } from 'vitest'
import { useEffect, type ReactNode } from 'react'
import type { User } from '@/lib/api'

vi.mock('@/lib/api', () => ({
  api: {
    auth: { me: vi.fn(), passwordResetConfig: vi.fn() },
  },
}))

import { api } from '@/lib/api'
import { AuthProvider, useAuth } from '@/hooks/useAuth'
import Login from '@/pages/Login'

const USER: User = {
  id: 1, email: 'admin@example.com', display_name: 'Admin', role: 'admin',
  is_active: true, totp_enabled: false, created_at: '2024-01-01T00:00:00Z',
  has_outstanding_welcome_token: false,
}
const RENAMED_USER: User = { ...USER, display_name: 'Admin (renamed)' }

/** Mirrors App.tsx's own Guard exactly — this test needs the real
 * redirect-to-/login-on-null-user behavior, not a stub of it, since the
 * bug is specifically about what happens after that redirect fires. */
function Guard({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth()
  if (loading) return <div className="auth-loading" />
  if (!user) return <Navigate to="/login" replace />
  return <>{children}</>
}

function ProtectedPage() {
  return <div>protected page</div>
}

// Captured once, outside the route tree that Guard unmounts — standing in
// for the fact that the real setToken(token, user) call (SecurityModal's
// savePassword) runs from a plain async function closure, not something
// tied to the component tree: it keeps executing and still reaches
// AuthProvider's state regardless of whether the component that started
// it is still mounted by the time it resolves. Rendered as a sibling of
// the routed tree, inside the same AuthProvider, so it captures a real
// setToken from the SAME provider instance Guard/Login read from.
let capturedSetToken: ((accessToken: string, user: User) => void) | null = null
function SetTokenCapture() {
  const { setToken, getAuthGeneration } = useAuth()
  // Captured in an effect, not during render: assigning to a variable
  // outside the component during render is itself a side effect React
  // (correctly) flags — this only needs to happen once setToken is
  // available, which an effect achieves without pretending it's part of
  // this component's own render output.
  //
  // Wrapped so this test's own call site still looks like the pre-
  // generation-guard signature (accessToken, user) — capturing
  // getAuthGeneration() fresh at call time, the same way
  // SecurityModal.savePassword captures it right before starting its own
  // request, not once up front. Since nothing else writes to this
  // provider during this test, the guard is a no-op here either way; this
  // is purely about keeping the real setToken signature satisfied.
  useEffect(() => {
    capturedSetToken = (accessToken, user) => setToken(accessToken, user, getAuthGeneration())
  }, [setToken, getAuthGeneration])
  return null
}

function TestApp() {
  return (
    <AuthProvider>
      <SetTokenCapture />
      <MemoryRouter initialEntries={['/protected']}>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<Guard><div>dashboard</div></Guard>} />
          <Route path="/protected" element={<Guard><ProtectedPage /></Guard>} />
        </Routes>
      </MemoryRouter>
    </AuthProvider>
  )
}

describe('Login redirects away once auth state is restored mid-race', () => {
  beforeEach(() => {
    localStorage.clear()
    capturedSetToken = null
    vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: false })
  })

  afterEach(() => {
    localStorage.clear()
  })

  it('navigates away from /login once setToken restores user after a stale-401-first redirect', async () => {
    localStorage.setItem('token', 'original-token')
    vi.mocked(api.auth.me).mockResolvedValue(USER)

    render(<TestApp />)
    await screen.findByText('protected page')

    // The older in-flight request's stale 401 arrives first — while
    // 'original-token' is still what's in localStorage, since the
    // password-change response hasn't come back yet. useAuth's own
    // handler correctly (from its own point of view) clears token/user;
    // Guard's very next render then has no user to show and redirects to
    // /login, unmounting the protected page (and, in the real app,
    // whatever modal was mid-flow inside it) along with it.
    act(() => {
      window.dispatchEvent(new CustomEvent('auth:unauthorized', { detail: { token: 'original-token' } }))
    })
    await screen.findByLabelText('Email')
    expect(screen.queryByText('protected page')).not.toBeInTheDocument()

    // The password-change response finally arrives. capturedSetToken was
    // obtained before the race started, from the same AuthProvider
    // instance — calling it now is exactly equivalent to
    // SecurityModal.savePassword's own setToken(result.access_token,
    // result) resolving after its component has already been unmounted
    // by the redirect above: the call still runs and still updates real
    // AuthProvider state, since it never depended on that component
    // still existing.
    expect(capturedSetToken).not.toBeNull()
    act(() => {
      capturedSetToken!('new-token', RENAMED_USER)
    })

    // Without Login's own redirect-when-authenticated effect, nothing
    // would notice `user` became truthy again and the form above would
    // stay on screen forever despite a fully valid, restored session.
    // Lands on "/" (Login's own navigate target), not back on the
    // original /protected route — this fix is "don't strand the user on
    // the login form," not route-restoration to wherever they started.
    await screen.findByText('dashboard')
    expect(screen.queryByLabelText('Email')).not.toBeInTheDocument()
  })
})
