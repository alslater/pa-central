/**
 * Users page — op_id reconciliation wiring, preparation-failure warning,
 * and the resend-welcome-email button label.
 *
 * doResetPassword and AddUserModal's save() both now check `op_id` first:
 * when the backend hands the send off to a background task, the frontend
 * must register it with LiveAlertsProvider (via registerPendingOp) so the
 * eventual outcome is reconciled over the admin-alerts SSE stream, rather
 * than assuming success or showing nothing.
 */
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { vi, beforeEach, afterEach, describe, it, expect } from 'vitest'
import type { User } from '@/lib/api'

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}))

// Defaults to the common case: the op is still genuinely pending (no
// SSE event had already arrived). Tests covering the early-arrival race
// override this per-test to return false and assert the "sending…" toast
// is correctly suppressed.
const registerPendingOp = vi.fn(() => true)
const discardEarlyResult = vi.fn()
const getSessionEpoch = vi.fn(() => 0)

vi.mock('@/hooks/useLiveAlerts', () => ({
  useLiveAlertsContext: () => ({
    count: 0, clear: vi.fn(), Toast: null,
    registerPendingOp, discardEarlyResult, getSessionEpoch,
  }),
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
  has_outstanding_welcome_token: false,
}
const TARGET: User = {
  id: 2, email: 'bob@example.com', display_name: 'Bob',
  role: 'viewer', is_active: true, totp_enabled: false, created_at: '2024-01-01T00:00:00Z',
  has_outstanding_welcome_token: false,
}
const TARGET_PENDING_WELCOME: User = { ...TARGET, has_outstanding_welcome_token: true }

function setup(users: User[] = [ADMIN, TARGET]) {
  vi.mocked(useAuth).mockReturnValue({
    user: ADMIN, loading: false, token: 'test-token',
    login: vi.fn(), completeTotp: vi.fn(), logout: vi.fn(), setToken: vi.fn(),
  } as any)
  vi.mocked(api.users.list).mockResolvedValue(users)
  vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: true })
  vi.stubGlobal('fetch', vi.fn().mockImplementation((url: unknown) => {
    throw new Error(`Unexpected fetch to ${url} — mock api methods instead`)
  }))
  return userEvent.setup()
}

async function openResetPrompt(user: ReturnType<typeof userEvent.setup>, name = 'Bob') {
  render(<MemoryRouter><Users /></MemoryRouter>)
  await user.click(await screen.findByText(name))
}

describe('doResetPassword preparation-failure warning', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

  it('shows a warning toast when password is null, reset_link_sent is false, op_id is null', async () => {
    const user = setup()
    vi.mocked(api.users.resetPassword).mockResolvedValue({
      password: null, reset_link_sent: false, op_id: null,
    })
    await openResetPrompt(user)
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))

    await waitFor(() => {
      expect(screen.getByText(/no reset email could be prepared/i)).toBeInTheDocument()
    })
    expect(registerPendingOp).not.toHaveBeenCalled()
  })
})

describe('doResetPassword op_id registration', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

  it('registers the pending op and shows a "sending" toast when op_id is present', async () => {
    const user = setup()
    vi.mocked(api.users.resetPassword).mockResolvedValue({
      password: null, reset_link_sent: null, op_id: 'op-reset-1',
    })
    await openResetPrompt(user)
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))

    await waitFor(() => {
      expect(registerPendingOp).toHaveBeenCalledWith(
        'op-reset-1',
        expect.objectContaining({ action: 'admin_reset', dismiss: expect.any(Function), epoch: 0 }),
      )
    })
    expect(await screen.findByText(/sending reset link/i)).toBeInTheDocument()
  })

  it('does not show a "sending" toast when registerPendingOp reports the outcome already arrived', async () => {
    // registerPendingOp returns false when an SSE event for this op_id had
    // already been buffered before this call — meaning it already rendered
    // the real, final toast itself. Showing "sending…" on top of that would
    // follow a real outcome with a stale message for an already-done op.
    registerPendingOp.mockReturnValueOnce(false)
    const user = setup()
    vi.mocked(api.users.resetPassword).mockResolvedValue({
      password: null, reset_link_sent: null, op_id: 'op-reset-early',
    })
    await openResetPrompt(user)
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))

    await waitFor(() => {
      expect(registerPendingOp).toHaveBeenCalledWith(
        'op-reset-early',
        expect.objectContaining({ action: 'admin_reset' }),
      )
    })
    expect(screen.queryByText(/sending reset link/i)).not.toBeInTheDocument()
  })

  it('treats admission-refused (reset_link_sent=false, op_id set) as a settled failure, not a pending op', async () => {
    // Regression: reset_password's own admission-refused branch returns
    // reset_link_sent=false AND a non-null op_id together — its own
    // comment is explicit that this is the final answer ("no further SSE
    // outcome will arrive beyond the attempted=False event it already
    // emitted"). Checking op_id before reset_link_sent would treat this
    // already-decided failure as still-pending whenever the SSE event it
    // refers to was missed, leaving a "sending…" toast that can never
    // resolve, since no second event is ever coming.
    const user = setup()
    vi.mocked(api.users.resetPassword).mockResolvedValue({
      password: null, reset_link_sent: false, op_id: 'op-refused',
    })
    await openResetPrompt(user)
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))

    // Distinct message from a true preparation failure (op_id null,
    // asserted separately below): admission-refused means preparation
    // succeeded and the queue was full, not that anything is
    // misconfigured — pointing an admin at SMTP/account settings for a
    // "try again shortly" problem was the bug this test guards against.
    expect(await screen.findByText(/too many pending admin actions/i)).toBeInTheDocument()
    expect(screen.queryByText(/no reset email could be prepared/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/sending reset link/i)).not.toBeInTheDocument()
    expect(registerPendingOp).not.toHaveBeenCalled()
    // The op_id is never registered on this branch (no future SSE event
    // will ever resolve it), so the only way to avoid leaving a matching
    // earlyResults entry stranded until the next unrelated SSE message's
    // opportunistic prune is to explicitly discard it here.
    expect(discardEarlyResult).toHaveBeenCalledWith('op-refused')
  })

  it('still shows the generated password once when op_id and reset_link_sent are both absent/false', async () => {
    const user = setup()
    vi.mocked(api.users.resetPassword).mockResolvedValue({
      password: 'generated-secret', reset_link_sent: false, op_id: null,
    })
    await openResetPrompt(user)
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))

    expect(await screen.findByText('generated-secret')).toBeInTheDocument()
    expect(registerPendingOp).not.toHaveBeenCalled()
  })

  it('does not lose the generated password to the row-refresh triggered by the same reset, even when that refresh is slow', async () => {
    // Regression: doResetPassword refreshes this row's data (for
    // has_outstanding_welcome_token) via the same call that also sets
    // newPassword. Using the page's ordinary load() for that refresh sets
    // loading=true, which unmounts the whole table — UserEditPanel
    // included — behind a "Loading…" placeholder until the refetch
    // resolves, destroying newPassword's state in the process. A mocked
    // fetch that happens to resolve within the same synchronous batch can
    // mask this entirely (verified directly: an instantly-resolving mock
    // never shows the bug), which is why this test deliberately holds the
    // second list() call open — matching how a real network request
    // actually takes non-zero time — before asserting the password is
    // still on screen.
    const user = setup()
    vi.mocked(api.users.resetPassword).mockResolvedValue({
      password: 'generated-secret', reset_link_sent: false, op_id: null,
    })
    await openResetPrompt(user)
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))

    let resolveRefresh: (users: typeof TARGET[]) => void
    vi.mocked(api.users.list).mockImplementationOnce(
      () => new Promise(resolve => { resolveRefresh = resolve })
    )
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))

    // While the row-refresh is still in flight: no "Loading…" placeholder,
    // and the password is already on screen.
    await waitFor(() => expect(screen.getByText('generated-secret')).toBeInTheDocument())
    expect(screen.queryByText(/^loading…$/i)).not.toBeInTheDocument()

    resolveRefresh!([TARGET])
    await waitFor(() => expect(api.users.list).toHaveBeenCalledTimes(2))
    // Still there once the refresh actually resolves.
    expect(screen.getByText('generated-secret')).toBeInTheDocument()
  })
})

describe('resend-welcome-email button label', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

  it('shows "Reset password" when the user has no outstanding welcome token', async () => {
    const user = setup([ADMIN, TARGET])
    render(<MemoryRouter><Users /></MemoryRouter>)
    await user.click(await screen.findByText('Bob'))
    expect(await screen.findByRole('button', { name: /^reset password$/i })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^resend welcome email$/i })).not.toBeInTheDocument()
  })

  it('shows "Resend welcome email" when the user has an outstanding welcome token', async () => {
    const user = setup([ADMIN, TARGET_PENDING_WELCOME])
    render(<MemoryRouter><Users /></MemoryRouter>)
    await user.click(await screen.findByText('Bob'))
    expect(await screen.findByRole('button', { name: /^resend welcome email$/i })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^reset password$/i })).not.toBeInTheDocument()
  })

  it('keeps the "Resend welcome email" label on the confirm button too', async () => {
    const user = setup([ADMIN, TARGET_PENDING_WELCOME])
    render(<MemoryRouter><Users /></MemoryRouter>)
    await user.click(await screen.findByText('Bob'))
    await user.click(await screen.findByRole('button', { name: /^resend welcome email$/i }))
    expect(await screen.findByRole('button', { name: /^resend welcome email$/i })).toBeInTheDocument()
  })

  it('refreshes to "Reset password" after a resend whose preparation failed and left no replacement token', async () => {
    // Regression: has_outstanding_welcome_token is settled server-side by
    // the time resetPassword's response returns (set_password retires the
    // old token; prepare_reset_email commits any replacement, before the
    // response is ever built) — but the `user` prop is a snapshot from the
    // last list() fetch. Without a reload after the reset, this row keeps
    // showing "Resend welcome email" even though the real welcome token is
    // now gone, and a second click would perform an ordinary admin reset
    // under the wrong label/email expectation.
    const user = setup([ADMIN, TARGET_PENDING_WELCOME])
    vi.mocked(api.users.resetPassword).mockResolvedValue({
      password: null, reset_link_sent: false, op_id: null,
    })
    // The reload triggered by doResetPassword's response must refetch —
    // this second resolution reflects the real post-reset state.
    vi.mocked(api.users.list).mockResolvedValueOnce([ADMIN, TARGET_PENDING_WELCOME])
      .mockResolvedValueOnce([ADMIN, TARGET])

    render(<MemoryRouter><Users /></MemoryRouter>)
    await user.click(await screen.findByText('Bob'))
    await user.click(await screen.findByRole('button', { name: /^resend welcome email$/i }))
    await user.click(await screen.findByRole('button', { name: /^resend welcome email$/i }))

    await waitFor(() => expect(api.users.list).toHaveBeenCalledTimes(2))
    expect(await screen.findByRole('button', { name: /^reset password$/i })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^resend welcome email$/i })).not.toBeInTheDocument()
  })

  it('reflects a genuinely successful resend as still having an outstanding welcome token', async () => {
    // The inverse direction, so the fix isn't just "always clear the
    // label": a resend that actually succeeds mints a fresh welcome token
    // (still outstanding), so the row must keep showing "Resend welcome
    // email" — not flip to "Reset password" just because a reset happened.
    const user = setup([ADMIN, TARGET_PENDING_WELCOME])
    vi.mocked(api.users.resetPassword).mockResolvedValue({
      password: null, reset_link_sent: null, op_id: 'op-resend-ok',
    })
    vi.mocked(api.users.list).mockResolvedValueOnce([ADMIN, TARGET_PENDING_WELCOME])
      .mockResolvedValueOnce([ADMIN, TARGET_PENDING_WELCOME])

    render(<MemoryRouter><Users /></MemoryRouter>)
    await user.click(await screen.findByText('Bob'))
    await user.click(await screen.findByRole('button', { name: /^resend welcome email$/i }))
    await user.click(await screen.findByRole('button', { name: /^resend welcome email$/i }))

    await waitFor(() => expect(api.users.list).toHaveBeenCalledTimes(2))
    expect(await screen.findByRole('button', { name: /^resend welcome email$/i })).toBeInTheDocument()
  })
})

describe('AddUserModal op_id registration', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

  async function openAddUser(user: ReturnType<typeof userEvent.setup>) {
    render(<MemoryRouter><Users /></MemoryRouter>)
    await user.click(await screen.findByRole('button', { name: /add user/i }))
    await waitFor(() =>
      expect(screen.getByText(/link to set their own password/i)).toBeInTheDocument()
    )
    await user.type(screen.getByLabelText(/display name/i), 'New Comer')
    await user.type(screen.getByLabelText(/^email/i), 'new@example.com')
  }

  it('registers the pending op and reports "pending" status when op_id is present', async () => {
    const user = setup([ADMIN])
    vi.mocked(api.auth.register).mockResolvedValue({
      ...ADMIN, id: 9, email: 'new@example.com', display_name: 'New',
      welcome_email_sent: null, welcome_link_still_valid: null, op_id: 'op-welcome-1',
    })
    await openAddUser(user)
    await user.click(screen.getByRole('button', { name: /create & send invite/i }))

    await waitFor(() => {
      expect(registerPendingOp).toHaveBeenCalledWith(
        'op-welcome-1',
        expect.objectContaining({ action: 'welcome_link', dismiss: expect.any(Function), epoch: 0 }),
      )
    })
    expect(await screen.findByText(/sending welcome link/i)).toBeInTheDocument()
  })

  it('does not show a "sending" toast when registerPendingOp reports the outcome already arrived', async () => {
    registerPendingOp.mockReturnValueOnce(false)
    const user = setup([ADMIN])
    vi.mocked(api.auth.register).mockResolvedValue({
      ...ADMIN, id: 9, email: 'new@example.com', display_name: 'New',
      welcome_email_sent: null, welcome_link_still_valid: null, op_id: 'op-welcome-early',
    })
    await openAddUser(user)
    await user.click(screen.getByRole('button', { name: /create & send invite/i }))

    await waitFor(() => {
      expect(registerPendingOp).toHaveBeenCalledWith(
        'op-welcome-early',
        expect.objectContaining({ action: 'welcome_link' }),
      )
    })
    expect(screen.queryByText(/sending welcome link/i)).not.toBeInTheDocument()
  })

  it('treats admission-refused (welcome_email_sent=false, op_id set) as a settled failure, not a pending op', async () => {
    // Same regression as reset_password's own admission-refused case:
    // register()'s comment is explicit this response is the settled
    // answer when admission is refused, even though it still carries an
    // op_id. Checking op_id first would leave a "sending…" toast that can
    // never resolve if the SSE event for it was ever missed.
    const user = setup([ADMIN])
    vi.mocked(api.auth.register).mockResolvedValue({
      ...ADMIN, id: 9, email: 'new@example.com', display_name: 'New',
      welcome_email_sent: false, welcome_link_still_valid: false, op_id: 'op-welcome-refused',
    })
    await openAddUser(user)
    await user.click(screen.getByRole('button', { name: /create & send invite/i }))

    // Distinct message from a true preparation failure (op_id null,
    // asserted separately below): admission-refused means preparation
    // succeeded and the admin-send queue was full, not that anything is
    // misconfigured.
    expect(await screen.findByText(/too many pending admin actions/i)).toBeInTheDocument()
    expect(screen.queryByText(/could not be prepared/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/sending welcome link/i)).not.toBeInTheDocument()
    expect(registerPendingOp).not.toHaveBeenCalled()
    // Same reasoning as reset_password's own admission-refused case: this
    // op_id is never registered, so it must be explicitly discarded rather
    // than left stranded in earlyResults.
    expect(discardEarlyResult).toHaveBeenCalledWith('op-welcome-refused')
  })

  it('shows the preparation-failure warning when op_id is absent and welcome_email_sent is false', async () => {
    // This is the only remaining way welcome_email_sent can be false: the
    // account exists but nothing was ever dispatched (no op_id) — every
    // dispatch-attempted case (admitted or admission-refused) always
    // carries an op_id, caught by the branch above this one.
    const user = setup([ADMIN])
    vi.mocked(api.auth.register).mockResolvedValue({
      ...ADMIN, id: 9, email: 'new@example.com', display_name: 'New',
      welcome_email_sent: false, welcome_link_still_valid: false, op_id: null,
    })
    await openAddUser(user)
    await user.click(screen.getByRole('button', { name: /create & send invite/i }))

    expect(await screen.findByText(/could not be prepared/i)).toBeInTheDocument()
    expect(registerPendingOp).not.toHaveBeenCalled()
  })

  it('does not register a pending op when self-service reset is off', async () => {
    // self_service === false: register() never touches op_id/
    // welcome_email_sent/welcome_link_still_valid at all — they stay at
    // their None/None/None defaults, since no welcome link is ever created.
    const user = setup([ADMIN])
    vi.mocked(api.auth.register).mockResolvedValue({
      ...ADMIN, id: 9, email: 'new@example.com', display_name: 'New',
      welcome_email_sent: null, welcome_link_still_valid: null, op_id: null,
    })
    await openAddUser(user)
    await user.click(screen.getByRole('button', { name: /create & send invite/i }))

    expect(await screen.findByText(/^user created$/i)).toBeInTheDocument()
    expect(registerPendingOp).not.toHaveBeenCalled()
  })
})

describe('epoch capture timing (regression)', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

  it('captures the session epoch before the await, not after (a logout mid-request must not silently mask a stale response)', async () => {
    const user = setup()
    let resolveResetPassword!: (v: { password: string | null; reset_link_sent: boolean | null; op_id: string | null }) => void
    vi.mocked(api.users.resetPassword).mockImplementation(
      () => new Promise(resolve => { resolveResetPassword = resolve })
    )
    // Simulate the epoch bumping (e.g. a concurrent logout) between the
    // capture and the await's resolution: getSessionEpoch is read
    // synchronously by doResetPassword *before* the await, so it must
    // observe 0 here even though it will return 1 for any later caller.
    getSessionEpoch.mockReturnValueOnce(0)

    await openResetPrompt(user)
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))
    await user.click(await screen.findByRole('button', { name: /^reset password$/i }))

    // Bump what getSessionEpoch would return from now on, mimicking a
    // logout firing while the request is still in flight.
    getSessionEpoch.mockReturnValue(1)

    resolveResetPassword({ password: null, reset_link_sent: null, op_id: 'op-x' })

    await waitFor(() => {
      expect(registerPendingOp).toHaveBeenCalledWith('op-x', expect.objectContaining({ epoch: 0 }))
    })
  })
})
