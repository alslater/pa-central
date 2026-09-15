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

vi.mock('@/hooks/useLiveAlerts', () => ({
  useLiveAlertsContext: () => ({
    count: 0, clear: vi.fn(), Toast: null,
    // Defaults to the common case: the op is still genuinely pending (no
    // SSE event had already arrived) — registerPendingOp's real contract
    // returns false only when it resolved an early-arrived event.
    registerPendingOp: vi.fn(() => true),
    getSessionEpoch: () => 0,
  }),
}))

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
  has_outstanding_welcome_token: false,
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
  // Every self-service-on send is now dispatched via dispatch_admin_action
  // and reported exclusively through SSE — register() can no longer
  // synchronously confirm a send, so the only realistic "success" shape it
  // returns is an admitted dispatch (op_id set, welcome_email_sent/
  // welcome_link_still_valid both null: "genuinely in flight" — see
  // RegisterOut's own docstring). Self-service-off never touches any of
  // these three fields at all.
  vi.mocked(api.auth.register).mockResolvedValue({
    ...ADMIN, id: 9, email: 'new@example.com', display_name: 'New',
    welcome_email_sent: null,
    welcome_link_still_valid: null,
    op_id: selfServiceEnabled ? 'op-default' : null,
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

  it('reports the welcome link is being sent, once the dispatch is admitted', async () => {
    // Every self-service-on send is now backgrounded via
    // dispatch_admin_action — register() itself never confirms delivery
    // synchronously. op_id set + registerPendingOp reporting genuinely
    // still-pending is what a real admitted dispatch looks like; the
    // eventual outcome (sent, or not) arrives later via the SSE
    // admin_action_result event.
    const user = setup(true)
    await openAddUser(user)
    await waitFor(() =>
      expect(screen.getByText(/link to set their own password/i)).toBeInTheDocument()
    )
    await fillIdentity(user)
    await user.click(screen.getByRole('button', { name: /create & send invite/i }))

    expect(await screen.findByText(/sending welcome link/i)).toBeInTheDocument()
  })

  it('warns rather than claiming success when preparation itself failed', async () => {
    // The only way welcome_email_sent can be false is when preparation
    // never got far enough to dispatch anything at all (no op_id) — every
    // dispatch-attempted case (admitted or admission-refused) always
    // carries an op_id and is reconciled via SSE instead. The account
    // still exists (register() never rolls it back), so the toast must
    // not claim nothing happened, but it must not claim an email is on
    // its way either.
    const user = setup(true)
    vi.mocked(api.auth.register).mockResolvedValue({
      ...ADMIN, id: 9, email: 'new@example.com', display_name: 'New',
      welcome_email_sent: false,
      welcome_link_still_valid: false,
      op_id: null,
    })
    await openAddUser(user)
    await waitFor(() =>
      expect(screen.getByText(/link to set their own password/i)).toBeInTheDocument()
    )
    await fillIdentity(user)
    await user.click(screen.getByRole('button', { name: /create & send invite/i }))

    expect(await screen.findByText(/could not be prepared/i)).toBeInTheDocument()
    expect(screen.queryByText(/sending welcome link/i)).not.toBeInTheDocument()
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
