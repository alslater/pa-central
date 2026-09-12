/**
 * Shell.tsx's SecurityModal — self password-change flow.
 *
 * A password change bumps token_epoch (backend's set_password), which
 * invalidates the very bearer token that authenticated the PATCH request
 * that made the change — this modal is only ever opened for the logged-in
 * user's own account (Shell always passes user.id), so every save here is
 * exactly that self-change case. Without installing the replacement token
 * the backend now returns, the user is told "Password changed" and then
 * silently logged out on their very next API call.
 */
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi, beforeEach, describe, it, expect } from 'vitest'

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}))

vi.mock('@/lib/api', () => ({
  api: {
    users: {
      update: vi.fn(),
    },
  },
}))

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import { SecurityModal } from '@/components/Shell'

const setToken = vi.fn()
const show = vi.fn()
const onClose = vi.fn()

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(useAuth).mockReturnValue({
    user: null, loading: false,
    login: vi.fn(), completeTotp: vi.fn(), logout: vi.fn(),
    setToken,
  })
})

async function changePassword() {
  const user = userEvent.setup()
  render(<SecurityModal userId={1} totpEnabled={false} onClose={onClose} show={show} />)
  await user.type(screen.getByLabelText('New password'), 'A-brand-new-password9')
  await user.type(screen.getByLabelText('Confirm new password'), 'A-brand-new-password9')
  await user.click(screen.getByRole('button', { name: /change password/i }))
}

describe('SecurityModal password change', () => {
  it('installs the replacement access token when the backend returns one', async () => {
    vi.mocked(api.users.update).mockResolvedValue({
      id: 1, email: 'a@b.com', display_name: 'A', role: 'viewer',
      is_active: true, totp_enabled: false, created_at: '2024-01-01T00:00:00Z',
      access_token: 'replacement-token',
    } as any)

    await changePassword()

    await waitFor(() => expect(setToken).toHaveBeenCalledWith('replacement-token'))
    expect(show).toHaveBeenCalledWith('Password changed')
  })

  it('does not call setToken when the response carries no access_token', async () => {
    // Defensive control: a response shape that (for whatever reason) omits
    // the field must not crash or install `undefined` as a token.
    vi.mocked(api.users.update).mockResolvedValue({
      id: 1, email: 'a@b.com', display_name: 'A', role: 'viewer',
      is_active: true, totp_enabled: false, created_at: '2024-01-01T00:00:00Z',
    } as any)

    await changePassword()

    await waitFor(() => expect(show).toHaveBeenCalledWith('Password changed'))
    expect(setToken).not.toHaveBeenCalled()
  })
})
