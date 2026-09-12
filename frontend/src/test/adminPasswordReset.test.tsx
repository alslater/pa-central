/**
 * Users page — admin-initiated password reset.
 *
 * The action always invalidates the current password, so the UI must say so
 * before the admin confirms, and must report the two outcomes differently:
 * a reset link emailed to the user, or a generated password to relay.
 */
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { vi, beforeEach, afterEach, describe, it, expect } from 'vitest'
import type { User } from '@/lib/api'

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}))

vi.mock('@/lib/api', () => ({
  api: {
    users: {
      list:          vi.fn(),
      delete:        vi.fn(),
      resetTotp:     vi.fn(),
      update:        vi.fn(),
      resetPassword: vi.fn(),
    },
    auth: { register: vi.fn(), passwordResetConfig: vi.fn() },
  },
}))

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import Users from '@/pages/Users'

const ADMIN: User = {
  id: 1, email: 'admin@example.com', display_name: 'Admin',
  role: 'admin', is_active: true, totp_enabled: false, created_at: '2024-01-01T00:00:00Z',
}
const TARGET: User = {
  id: 2, email: 'bob@example.com', display_name: 'Bob',
  role: 'viewer', is_active: true, totp_enabled: false, created_at: '2024-01-01T00:00:00Z',
}

function setup() {
  vi.mocked(useAuth).mockReturnValue({
    user: ADMIN, loading: false,
    login: vi.fn(), completeTotp: vi.fn(), logout: vi.fn(),
  } as any)
  vi.mocked(api.users.list).mockResolvedValue([ADMIN, TARGET])
  vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: true })
  vi.stubGlobal('fetch', vi.fn().mockImplementation((url: unknown) => {
    throw new Error(`Unexpected fetch to ${url} — mock api methods instead`)
  }))
  return userEvent.setup()
}

/** Expand Bob's row and click through to the confirmation prompt. */
async function openResetPrompt(user: ReturnType<typeof userEvent.setup>) {
  render(<MemoryRouter><Users /></MemoryRouter>)
  await user.click(await screen.findByText('Bob'))
  await user.click(await screen.findByRole('button', { name: /^reset password$/i }))
}

/** Run one reset on the already-rendered page: open the prompt, confirm.
 *  Used for the second and later resets in a test — calling openResetPrompt
 *  again would mount a second copy of the page instead. */
async function resetAgain(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: /^reset password$/i }))
  await user.click(await screen.findByRole('button', { name: /^reset password$/i }))
}

describe('Users page — admin password reset', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

  it('warns that the password is invalidated before the admin confirms', async () => {
    const user = setup()
    await openResetPrompt(user)

    // The admin must know this locks Bob out now, not once he clicks a link.
    expect(await screen.findByText(/invalidate this password now/i)).toBeInTheDocument()
    expect(screen.getByText(/will need the reset to sign in again/i)).toBeInTheDocument()
    expect(api.users.resetPassword).not.toHaveBeenCalled()
  })

  it('cancelling does not call the API', async () => {
    const user = setup()
    await openResetPrompt(user)
    await user.click(screen.getByRole('button', { name: /cancel/i }))

    expect(api.users.resetPassword).not.toHaveBeenCalled()
  })

  it('reports that the password was invalidated and a link sent', async () => {
    const user = setup()
    vi.mocked(api.users.resetPassword).mockResolvedValue({
      password: null, reset_link_sent: true,
    })
    await openResetPrompt(user)
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))

    await waitFor(() => expect(api.users.resetPassword).toHaveBeenCalledWith(2))
    // The toast names the recipient; the address also appears in the table
    // row, so match the whole message rather than the address alone.
    expect(
      await screen.findByText(/password invalidated — reset link emailed to bob@example\.com/i)
    ).toBeInTheDocument()
  })

  it('shows the generated password once when no link was sent', async () => {
    const user = setup()
    vi.mocked(api.users.resetPassword).mockResolvedValue({
      password: 'generated-secret-value', reset_link_sent: false,
    })
    await openResetPrompt(user)
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))

    expect(await screen.findByText('generated-secret-value')).toBeInTheDocument()
    expect(screen.getByText(/won't be shown again/i)).toBeInTheDocument()
  })

  // Every reset invalidates the current credential, so a password shown from
  // an earlier reset is already dead. Leaving it on screen invites the admin
  // to copy and relay something that no longer works.

  it('clears a previous password when a later reset emails a link instead', async () => {
    const user = setup()
    vi.mocked(api.users.resetPassword)
      .mockResolvedValueOnce({ password: 'first-generated-password', reset_link_sent: false })
      .mockResolvedValueOnce({ password: null, reset_link_sent: true })
    await openResetPrompt(user)
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))
    expect(await screen.findByText('first-generated-password')).toBeInTheDocument()

    await resetAgain(user)

    await waitFor(() => expect(api.users.resetPassword).toHaveBeenCalledTimes(2))
    expect(screen.queryByText('first-generated-password')).not.toBeInTheDocument()
    expect(await screen.findByText(/password invalidated/i)).toBeInTheDocument()
  })

  it('clears a previous password when a later reset fails', async () => {
    const user = setup()
    vi.mocked(api.users.resetPassword)
      .mockResolvedValueOnce({ password: 'first-generated-password', reset_link_sent: false })
      .mockRejectedValueOnce(new Error('the reset email could not be sent'))
    await openResetPrompt(user)
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))
    expect(await screen.findByText('first-generated-password')).toBeInTheDocument()

    await resetAgain(user)

    await waitFor(() => expect(api.users.resetPassword).toHaveBeenCalledTimes(2))
    // The failed attempt invalidated the password too, so the old one is
    // doubly dead — and there is no new one to show.
    expect(screen.queryByText('first-generated-password')).not.toBeInTheDocument()
    expect(await screen.findByText(/could not be sent/i)).toBeInTheDocument()
  })

  it('shows only the newest password across consecutive resets', async () => {
    const user = setup()
    vi.mocked(api.users.resetPassword)
      .mockResolvedValueOnce({ password: 'first-generated-password', reset_link_sent: false })
      .mockResolvedValueOnce({ password: 'second-generated-password', reset_link_sent: false })
    await openResetPrompt(user)
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))
    expect(await screen.findByText('first-generated-password')).toBeInTheDocument()

    await resetAgain(user)

    expect(await screen.findByText('second-generated-password')).toBeInTheDocument()
    expect(screen.queryByText('first-generated-password')).not.toBeInTheDocument()
  })

  it('surfaces a failed send instead of implying success', async () => {
    const user = setup()
    vi.mocked(api.users.resetPassword).mockRejectedValue(
      new Error('The password has been invalidated, but the reset email could not be sent')
    )
    await openResetPrompt(user)
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))

    expect(await screen.findByText(/could not be sent/i)).toBeInTheDocument()
  })
})
