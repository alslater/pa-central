/**
 * Users page — Add User, welcome-link vs admin-set password.
 *
 * With self-service reset enabled a new account is handed over by emailing
 * the user a link to set their own password, so the admin never types (or
 * relays) a credential. With it disabled there is no way to deliver a link,
 * so the password field stays.
 */
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { vi, beforeEach, afterEach, describe, it, expect } from 'vitest'
import type { User } from '@/lib/api'

vi.mock('@/hooks/useAuth', () => ({ useAuth: vi.fn() }))

vi.mock('@/lib/api', () => ({
  api: {
    users: {
      list: vi.fn(), delete: vi.fn(), resetTotp: vi.fn(),
      update: vi.fn(), resetPassword: vi.fn(),
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

function setup(selfServiceEnabled: boolean) {
  vi.mocked(useAuth).mockReturnValue({
    user: ADMIN, loading: false,
    login: vi.fn(), completeTotp: vi.fn(), logout: vi.fn(),
  } as any)
  vi.mocked(api.users.list).mockResolvedValue([ADMIN])
  vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({
    self_service_enabled: selfServiceEnabled,
  })
  vi.mocked(api.auth.register).mockResolvedValue({
    ...ADMIN, id: 9, email: 'new@example.com', display_name: 'New',
    welcome_email_sent: selfServiceEnabled ? true : null,
    welcome_link_still_valid: selfServiceEnabled ? true : null,
  })
  vi.stubGlobal('fetch', vi.fn().mockImplementation((url: unknown) => {
    throw new Error(`Unexpected fetch to ${url} — mock api methods instead`)
  }))
  return userEvent.setup()
}

async function openAddUser(user: ReturnType<typeof userEvent.setup>) {
  render(<MemoryRouter><Users /></MemoryRouter>)
  await user.click(await screen.findByRole('button', { name: /add user/i }))
}

async function fillIdentity(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText(/display name/i), 'New Comer')
  await user.type(screen.getByLabelText(/^email/i), 'new@example.com')
}

describe('Add user — self-service enabled', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

  it('offers no password field, explaining the invite instead', async () => {
    const user = setup(true)
    await openAddUser(user)

    await waitFor(() =>
      expect(screen.getByText(/link to set their own password/i)).toBeInTheDocument()
    )
    expect(screen.queryByLabelText(/password/i)).not.toBeInTheDocument()
  })

  it('creates the user without sending a password', async () => {
    const user = setup(true)
    await openAddUser(user)
    await waitFor(() =>
      expect(screen.getByText(/link to set their own password/i)).toBeInTheDocument()
    )
    await fillIdentity(user)
    await user.click(screen.getByRole('button', { name: /create & send invite/i }))

    await waitFor(() => expect(api.auth.register).toHaveBeenCalled())
    const payload = vi.mocked(api.auth.register).mock.calls[0][0]
    // Omitted entirely, not sent empty — the backend rejects a supplied one.
    expect(payload).not.toHaveProperty('password')
    expect(payload.email).toBe('new@example.com')
  })

  it('confirms the invite was emailed', async () => {
    const user = setup(true)
    await openAddUser(user)
    await waitFor(() =>
      expect(screen.getByText(/link to set their own password/i)).toBeInTheDocument()
    )
    await fillIdentity(user)
    await user.click(screen.getByRole('button', { name: /create & send invite/i }))

    expect(await screen.findByText(/invite emailed/i)).toBeInTheDocument()
  })

  it('warns rather than claiming success when delivery is not confirmed', async () => {
    // The backend never rolls the account back for a delivery problem —
    // register() always resolves with 201 and welcome_email_sent reflects
    // whether the send was confirmed. false does not distinguish a
    // certain failure from a merely unconfirmed one, so the toast must
    // not claim the invite was emailed, but it also must not claim the
    // account was not created — it was.
    //
    // welcome_link_still_valid is mocked as `false` here, not `null` —
    // issue_reset_token's real IssueResult(sent=False, still_live=False)
    // never checks token liveness at all on a send failure, so it reports
    // still_live=False as a placeholder alongside sent=False, not None.
    // A `null` mock here previously let this test pass while the frontend
    // checked welcome_link_still_valid before welcome_email_sent and
    // mistook this exact combination for "sent, but the link is already
    // invalid" against the real backend response.
    const user = setup(true)
    vi.mocked(api.auth.register).mockResolvedValue({
      ...ADMIN, id: 9, email: 'new@example.com', display_name: 'New',
      welcome_email_sent: false,
      welcome_link_still_valid: false,
    })
    await openAddUser(user)
    await waitFor(() =>
      expect(screen.getByText(/link to set their own password/i)).toBeInTheDocument()
    )
    await fillIdentity(user)
    await user.click(screen.getByRole('button', { name: /create & send invite/i }))

    expect(await screen.findByText(/could not be confirmed/i)).toBeInTheDocument()
    expect(screen.queryByText(/invite emailed/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/link is already invalid/i)).not.toBeInTheDocument()
  })

  it('warns when the email was sent but its link is already invalid', async () => {
    // A concurrent event (most commonly, an admin disabling self-service
    // reset or clearing its SMTP config while this send was in flight)
    // can retire the token even though the email itself was genuinely
    // delivered — welcome_email_sent=true, welcome_link_still_valid=false.
    // A plain "invite emailed" success would tell the admin nothing is
    // wrong when the link the user is about to click is already dead.
    const user = setup(true)
    vi.mocked(api.auth.register).mockResolvedValue({
      ...ADMIN, id: 9, email: 'new@example.com', display_name: 'New',
      welcome_email_sent: true,
      welcome_link_still_valid: false,
    })
    await openAddUser(user)
    await waitFor(() =>
      expect(screen.getByText(/link to set their own password/i)).toBeInTheDocument()
    )
    await fillIdentity(user)
    await user.click(screen.getByRole('button', { name: /create & send invite/i }))

    expect(await screen.findByText(/link is already invalid/i)).toBeInTheDocument()
    expect(screen.queryByText(/^User created — invite emailed$/i)).not.toBeInTheDocument()
  })
})

describe('Add user — before the credential mode is known', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

  // Neither answer is a safe default while the mode is unknown: with
  // self-service on the backend rejects a supplied password, with it off a
  // password is required. Defaulting either way walks the admin into a 400
  // they cannot act on, so Add User waits until the mode is known.

  it('is unavailable while the config request is still pending', async () => {
    setup(true)
    vi.mocked(api.auth.passwordResetConfig).mockReturnValue(
      new Promise(() => {}) as never
    )
    render(<MemoryRouter><Users /></MemoryRouter>)

    expect(await screen.findByRole('button', { name: /add user/i })).toBeDisabled()
  })

  it('does not offer a password field once the config resolves to self-service', async () => {
    let resolve!: (v: { self_service_enabled: boolean }) => void
    const user = setup(true)
    vi.mocked(api.auth.passwordResetConfig).mockReturnValue(
      new Promise(r => { resolve = r }) as never
    )
    render(<MemoryRouter><Users /></MemoryRouter>)

    const button = await screen.findByRole('button', { name: /add user/i })
    expect(button).toBeDisabled()

    resolve({ self_service_enabled: true })
    await waitFor(() => expect(button).toBeEnabled())

    await user.click(button)
    expect(screen.queryByLabelText(/password/i)).not.toBeInTheDocument()
    expect(await screen.findByText(/link to set their own password/i)).toBeInTheDocument()
  })

  it('reports a failed config read and blocks Add User', async () => {
    setup(true)
    vi.mocked(api.auth.passwordResetConfig).mockRejectedValue(new Error('offline'))
    render(<MemoryRouter><Users /></MemoryRouter>)

    expect(await screen.findByText(/could not load the password reset mode/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /add user/i })).toBeDisabled()
  })

  it('recovers when the retry succeeds', async () => {
    const user = setup(true)
    vi.mocked(api.auth.passwordResetConfig)
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce({ self_service_enabled: true })
    render(<MemoryRouter><Users /></MemoryRouter>)

    await user.click(await screen.findByRole('button', { name: /retry/i }))

    await waitFor(() =>
      expect(screen.getByRole('button', { name: /add user/i })).toBeEnabled()
    )
    expect(screen.queryByText(/could not load the password reset mode/i)).not.toBeInTheDocument()
  })
})

describe('Add user — self-service disabled', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

  it('still requires an admin-set password', async () => {
    const user = setup(false)
    await openAddUser(user)

    const pw = await screen.findByLabelText(/password/i)
    await fillIdentity(user)

    // No password yet — creation must stay blocked.
    expect(screen.getByRole('button', { name: /create user/i })).toBeDisabled()

    await user.type(pw, 'a-long-enough-password')
    await user.click(screen.getByRole('button', { name: /create user/i }))

    await waitFor(() => expect(api.auth.register).toHaveBeenCalled())
    expect(vi.mocked(api.auth.register).mock.calls[0][0].password).toBe('a-long-enough-password')
  })

  it('does not claim an invite was emailed', async () => {
    const user = setup(false)
    await openAddUser(user)
    await fillIdentity(user)
    await user.type(await screen.findByLabelText(/password/i), 'a-long-enough-password')
    await user.click(screen.getByRole('button', { name: /create user/i }))

    expect(await screen.findByText(/^user created$/i)).toBeInTheDocument()
  })

  it('does not treat six emoji as a 12-character password', async () => {
    // String.prototype.length counts UTF-16 code units — each emoji
    // outside the Basic Multilingual Plane is a surrogate pair, so six
    // emoji report length 12. The backend's Pydantic min_length=12 on
    // UserCreate.password counts Unicode code points (Python's len()),
    // which sees 6 and rejects with a 422. Six emoji must still be
    // treated as too short here, or Create user submits something the
    // API then rejects.
    const user = setup(false)
    await openAddUser(user)
    await fillIdentity(user)

    const sixEmoji = '😀😀😀😀😀😀'
    expect(sixEmoji.length).toBe(12)
    await user.type(await screen.findByLabelText(/password/i), sixEmoji)

    expect(screen.getByRole('button', { name: /create user/i })).toBeDisabled()
    expect(api.auth.register).not.toHaveBeenCalled()
  })

  it('does not treat 40 accented characters as a submittable-length password', async () => {
    // bcrypt hashes only the first 72 *bytes* of its input, and the
    // backend's UserCreate.password validator
    // (_reject_password_over_bcrypt_limit) rejects anything past that with
    // a 422. 40 "é" characters is 40 Unicode code points — well past the
    // 12-character minimum, and not caught by codePointLength — but 80
    // UTF-8 bytes, past the 72-byte limit. Without a byte-length check
    // here, this value looked like an ordinary long password and was
    // submitted, only to be rejected by the API with no explanation shown
    // in this form.
    const user = setup(false)
    await openAddUser(user)
    await fillIdentity(user)

    const fortyAccented = 'é'.repeat(40)
    await user.type(await screen.findByLabelText(/password/i), fortyAccented)

    expect(screen.getByRole('button', { name: /create user/i })).toBeDisabled()
    expect(screen.getByText(/too long/i)).toBeInTheDocument()
    expect(api.auth.register).not.toHaveBeenCalled()
  })
})
