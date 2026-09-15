/**
 * ResetPassword.tsx — clearing the local session on a successful reset.
 *
 * /reset-password is deliberately reachable while signed in (someone
 * whose password was just admin-reset needs to reach it even though the
 * browser may still hold their now-revoked old session; see the page's
 * own comment on the missing-token notice). A successful reset bumps
 * token_epoch server-side (set_password), revoking every bearer token
 * already issued to the account — including whatever this browser
 * currently holds, if the person completing the reset happens to already
 * be signed in as that same account. Without clearing that local session,
 * "Go to sign in" navigates to /login while AuthProvider.user is still
 * the stale pre-reset user — Login's own redirect-when-authenticated
 * effect then bounces straight back into the app on a session the
 * backend has already revoked.
 */
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { vi, beforeEach, afterEach, describe, it, expect } from 'vitest'

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}))

vi.mock('@/lib/api', () => ({
  api: {
    auth: {
      passwordResetConfig: vi.fn(),
      resetPassword: vi.fn(),
    },
  },
}))

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import ResetPassword from '@/pages/ResetPassword'

const logout = vi.fn()
const navigate = vi.fn()

vi.mock('react-router', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router')>()
  return { ...actual, useNavigate: () => navigate }
})

function renderAt(hash: string) {
  window.history.pushState({}, '', `/reset-password${hash}`)
  return render(
    <MemoryRouter initialEntries={[`/reset-password${hash}`]}>
      <ResetPassword />
    </MemoryRouter>
  )
}

describe('ResetPassword clears the local session on success', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useAuth).mockReturnValue({
      user: null, loading: false, token: null,
      login: vi.fn(), completeTotp: vi.fn(), logout, setToken: vi.fn(),
      getAuthGeneration: vi.fn(() => 0), beginPasswordChange: vi.fn(() => true), endPasswordChange: vi.fn(),
    })
    vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: true })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('calls logout() after a successful reset, before showing "Go to sign in"', async () => {
    vi.mocked(api.auth.resetPassword).mockResolvedValue(undefined)
    const user = userEvent.setup()

    renderAt('#token=abc123')
    await user.type(await screen.findByLabelText('New password'), 'a-brand-new-password-1')
    await user.type(screen.getByLabelText('Confirm new password'), 'a-brand-new-password-1')
    await user.click(screen.getByRole('button', { name: /set new password/i }))

    await waitFor(() => expect(screen.getByRole('button', { name: /go to sign in/i })).toBeInTheDocument())
    // logout() must have already run by the time the success screen (and
    // its "Go to sign in" button) appears — not merely "eventually", since
    // a signed-in AuthProvider.user still being stale at the moment that
    // button becomes clickable is exactly the bug this covers.
    expect(logout).toHaveBeenCalledTimes(1)
  })

  it('does NOT call logout() when the reset fails', async () => {
    // The stale session belongs to whatever account this browser was
    // signed in as — a failed reset attempt (bad/expired/already-used
    // token) didn't actually change anything server-side, so there is
    // nothing to invalidate and no reason to sign this browser out of
    // whatever session it already had.
    vi.mocked(api.auth.resetPassword).mockRejectedValue(new Error('Invalid or expired token'))
    const user = userEvent.setup()

    renderAt('#token=abc123')
    await user.type(await screen.findByLabelText('New password'), 'a-brand-new-password-1')
    await user.type(screen.getByLabelText('Confirm new password'), 'a-brand-new-password-1')
    await user.click(screen.getByRole('button', { name: /set new password/i }))

    await waitFor(() => expect(screen.getByText(/invalid or expired token/i)).toBeInTheDocument())
    expect(logout).not.toHaveBeenCalled()
  })

  it('"Go to sign in" navigates to /login after the session has been cleared', async () => {
    vi.mocked(api.auth.resetPassword).mockResolvedValue(undefined)
    const user = userEvent.setup()

    renderAt('#token=abc123')
    await user.type(await screen.findByLabelText('New password'), 'a-brand-new-password-1')
    await user.type(screen.getByLabelText('Confirm new password'), 'a-brand-new-password-1')
    await user.click(screen.getByRole('button', { name: /set new password/i }))

    const goToSignIn = await screen.findByRole('button', { name: /go to sign in/i })
    await user.click(goToSignIn)

    expect(navigate).toHaveBeenCalledWith('/login')
    // logout() ran before this click (asserted above), not because of it —
    // by the time this button is even clickable, AuthProvider.user is
    // already null, so Login's redirect-when-authenticated effect has
    // nothing to bounce back on.
    expect(logout).toHaveBeenCalledTimes(1)
  })
})
