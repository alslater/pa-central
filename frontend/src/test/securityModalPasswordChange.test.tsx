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
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
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
const beginPasswordChange = vi.fn(() => true)
const endPasswordChange = vi.fn()
// Fixed, arbitrary value: what matters to these tests is that savePassword
// captures IT (via getAuthGeneration) and passes it straight through to
// setToken's third argument — the race that value guards against
// (useAuth.tsx's own docstring) is covered by useAuth's own test suite,
// not re-tested here against a mocked useAuth.
const AUTH_GENERATION = 7

beforeEach(() => {
  vi.clearAllMocks()
  beginPasswordChange.mockReturnValue(true)
  vi.mocked(useAuth).mockReturnValue({
    user: null, loading: false, token: 'test-token',
    login: vi.fn(), completeTotp: vi.fn(), logout: vi.fn(),
    setToken, getAuthGeneration: () => AUTH_GENERATION,
    beginPasswordChange, endPasswordChange,
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
  it('installs the replacement access token and fresh user when the backend returns one', async () => {
    const result = {
      id: 1, email: 'a@b.com', display_name: 'A', role: 'viewer',
      is_active: true, totp_enabled: false, created_at: '2024-01-01T00:00:00Z',
      access_token: 'replacement-token',
    }
    vi.mocked(api.users.update).mockResolvedValue(result as any)

    await changePassword()

    // Passing the whole PATCH response (not just its access_token) lets
    // setToken restore `user` in the same call — see useAuth's own
    // docstring for why: an older in-flight request's stale 401 for the
    // pre-change token can otherwise clear `user` in the window before
    // this call runs, and Guard (App.tsx) checks `user`, not `token`. The
    // third argument is the generation captured via getAuthGeneration()
    // before the PATCH started — see useAuth.tsx's setToken docstring for
    // the race (a save racing an explicit logout or fresh login) that
    // value lets setToken detect and silently ignore if superseded. (Two
    // overlapping SecurityModal saves against EACH OTHER are a separate
    // concern, serialized by beginPasswordChange/endPasswordChange —
    // covered by its own describe block below, not this one.)
    await waitFor(() => expect(setToken).toHaveBeenCalledWith('replacement-token', result, AUTH_GENERATION))
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

describe('SecurityModal password change — serialized against an overlapping change', () => {
  // The lock (useAuth.tsx's beginPasswordChange/endPasswordChange) lives
  // in AuthProvider, not this component's own local state, precisely so
  // it survives this component unmounting and a fresh instance mounting
  // in its place — see beginPasswordChange's own docstring for the race
  // this closes: the generation guard alone could keep a stale response
  // over the server's real current winner, since arrival order at the
  // browser is not the same thing as commit order on the server.
  it('refuses to start a request when beginPasswordChange reports one is already in flight', async () => {
    beginPasswordChange.mockReturnValue(false)
    const user = userEvent.setup()

    render(<SecurityModal userId={1} totpEnabled={false} onClose={onClose} show={show} />)
    await user.type(screen.getByLabelText('New password'), 'A-brand-new-password9')
    await user.type(screen.getByLabelText('Confirm new password'), 'A-brand-new-password9')
    await user.click(screen.getByRole('button', { name: /change password/i }))

    // Never even attempts the request — this is what actually prevents
    // two overlapping PATCHes from existing at all, not merely from both
    // succeeding at installing their own result.
    expect(api.users.update).not.toHaveBeenCalled()
    expect(await screen.findByText(/already in progress/i)).toBeInTheDocument()
  })

  it('releases the lock when the request succeeds', async () => {
    vi.mocked(api.users.update).mockResolvedValue({
      id: 1, email: 'a@b.com', display_name: 'A', role: 'viewer',
      is_active: true, totp_enabled: false, created_at: '2024-01-01T00:00:00Z',
      access_token: 'replacement-token',
    } as any)

    await changePassword()

    await waitFor(() => expect(endPasswordChange).toHaveBeenCalledTimes(1))
  })

  it('releases the lock when the request fails, so a retry is not permanently blocked', async () => {
    vi.mocked(api.users.update).mockRejectedValue(new Error('network error'))

    await changePassword()

    await waitFor(() => expect(endPasswordChange).toHaveBeenCalledTimes(1))
  })
})

describe('SecurityModal password validation', () => {
  it('rejects a password that is long by .length but short by code points', async () => {
    // Four emoji + "Aa1!": .length is 12 (each emoji is a 2-unit surrogate
    // pair), passing a naive `.length < 12` check, but only 8 actual code
    // points — under Pydantic's 12-code-point minimum. Set directly via
    // fireEvent rather than userEvent.type: typing astral-plane characters
    // keystroke-by-keystroke is unreliable in jsdom, and what matters here
    // is the value ultimately held by the input, not the keystrokes.
    render(<SecurityModal userId={1} totpEnabled={false} onClose={onClose} show={show} />)
    const password = '😀😀😀😀Aa1!'
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: password } })
    fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: password } })
    fireEvent.click(screen.getByRole('button', { name: /change password/i }))

    await waitFor(() => expect(screen.getByText(/at least 12 characters/i)).toBeInTheDocument())
    expect(api.users.update).not.toHaveBeenCalled()
  })

  it('rejects a password within the code-point minimum but over the UTF-8 byte limit', async () => {
    // "Aa1" + 35 "é": 38 code points (well past the 12 minimum, and passes
    // the 3-of-4 complexity check), but 73 UTF-8 bytes — one over bcrypt's
    // 72-byte limit, which the backend's own validator rejects with a 422.
    render(<SecurityModal userId={1} totpEnabled={false} onClose={onClose} show={show} />)
    const password = 'Aa1' + 'é'.repeat(35)
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: password } })
    fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: password } })
    fireEvent.click(screen.getByRole('button', { name: /change password/i }))

    await waitFor(() => expect(screen.getByText(/72 bytes/i)).toBeInTheDocument())
    expect(api.users.update).not.toHaveBeenCalled()
  })

  it('accepts a password within both the code-point minimum and the byte limit', async () => {
    vi.mocked(api.users.update).mockResolvedValue({
      id: 1, email: 'a@b.com', display_name: 'A', role: 'viewer',
      is_active: true, totp_enabled: false, created_at: '2024-01-01T00:00:00Z',
    } as any)
    await changePassword()

    await waitFor(() => expect(show).toHaveBeenCalledWith('Password changed'))
    expect(api.users.update).toHaveBeenCalledWith(1, { password: 'A-brand-new-password9' })
  })
})
