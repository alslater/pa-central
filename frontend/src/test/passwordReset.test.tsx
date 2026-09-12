/**
 * Self-service password reset UI.
 *
 * Covers the three places the feature surfaces: the "Forgot password?" entry
 * point on the login page (which must only appear when the deployment has it
 * switched on), the reset-link landing page, and the SMTP gate on the admin
 * settings toggle.
 */
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { vi, beforeEach, describe, it, expect } from 'vitest'

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}))

vi.mock('@/lib/api', () => ({
  api: {
    auth: {
      login: vi.fn(),
      totpVerify: vi.fn(),
      passwordResetConfig: vi.fn(),
      forgotPassword: vi.fn(),
      resetPassword: vi.fn(),
    },
    systemSettings: { list: vi.fn(), update: vi.fn(), passwordResetReadiness: vi.fn() },
  },
}))

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import Login from '@/pages/Login'
import ResetPassword from '@/pages/ResetPassword'
import SystemSettings from '@/pages/SystemSettings'

const mockAdmin = { id: 1, email: 'admin@example.com', display_name: 'Admin', role: 'admin' as const }

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(useAuth).mockReturnValue({ user: mockAdmin, login: vi.fn(), completeTotp: vi.fn() } as any)
  vi.mocked(api.systemSettings.update).mockResolvedValue([])
})

// ── Login entry point ─────────────────────────────────────────────────────────

describe('Login — "Forgot password?" entry point', () => {
  it('is hidden when self-service reset is disabled', async () => {
    vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: false })
    render(<MemoryRouter><Login /></MemoryRouter>)

    await screen.findByLabelText(/^Email$/i)
    await waitFor(() => expect(api.auth.passwordResetConfig).toHaveBeenCalled())
    expect(screen.queryByRole('button', { name: /forgot password/i })).not.toBeInTheDocument()
  })

  it('is hidden when the config request fails', async () => {
    // A deployment that can't answer must not advertise a flow that won't work.
    vi.mocked(api.auth.passwordResetConfig).mockRejectedValue(new Error('offline'))
    render(<MemoryRouter><Login /></MemoryRouter>)

    await screen.findByLabelText(/^Email$/i)
    await waitFor(() => expect(api.auth.passwordResetConfig).toHaveBeenCalled())
    expect(screen.queryByRole('button', { name: /forgot password/i })).not.toBeInTheDocument()
  })

  it('is shown when self-service reset is enabled', async () => {
    vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: true })
    render(<MemoryRouter><Login /></MemoryRouter>)

    expect(await screen.findByRole('button', { name: /forgot password/i })).toBeInTheDocument()
  })

  it('submits the address and confirms without revealing whether it exists', async () => {
    vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: true })
    vi.mocked(api.auth.forgotPassword).mockResolvedValue({ ok: true })
    const user = userEvent.setup()
    render(<MemoryRouter><Login /></MemoryRouter>)

    await user.click(await screen.findByRole('button', { name: /forgot password/i }))
    await user.type(await screen.findByLabelText(/^Email$/i), 'someone@example.com')
    await user.click(screen.getByRole('button', { name: /send reset link/i }))

    expect(api.auth.forgotPassword).toHaveBeenCalledWith('someone@example.com')
    // "If an account exists" — never a confirmation that it does.
    expect(await screen.findByText(/if an account exists/i)).toBeInTheDocument()
  })
})

// ── Reset landing page ────────────────────────────────────────────────────────

describe('ResetPassword page', () => {
  /** `entry` is the path portion after /reset-password — the token now
   *  arrives in the fragment (`#token=…`), which never reaches the server. */
  function renderAt(entry: string) {
    return render(
      <MemoryRouter initialEntries={[`/reset-password${entry}`]}>
        <ResetPassword />
      </MemoryRouter>
    )
  }

  it('still offers the form when the feature has since been switched off', async () => {
    // An already-issued link stays usable: the backend retires outstanding
    // tokens when the feature is disabled rather than refusing them, so a
    // link that still exists is a link that still works. Hiding the form
    // would strand exactly the people who cannot recover any other way — an
    // admin-reset victim whose password is already invalidated, or a new
    // account whose only credential is this link.
    vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: false })
    vi.mocked(api.auth.resetPassword).mockResolvedValue(undefined)
    const user = userEvent.setup()
    renderAt('#token=abc123')

    await user.type(await screen.findByLabelText(/^New password$/i), 'a-brand-new-password')
    await user.type(screen.getByLabelText(/^Confirm new password$/i), 'a-brand-new-password')
    await user.click(screen.getByRole('button', { name: /set new password/i }))

    expect(api.auth.resetPassword).toHaveBeenCalledWith('abc123', 'a-brand-new-password')
    expect(await screen.findByText(/password has been updated/i)).toBeInTheDocument()
  })

  it('mentions the feature being off only when there is no token to act on', async () => {
    vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: false })
    renderAt('')

    expect(await screen.findByText(/not enabled/i)).toBeInTheDocument()
    expect(screen.queryByLabelText(/^New password$/i)).not.toBeInTheDocument()
  })

  it('reads the token from the URL fragment', async () => {
    // The fragment is never sent to the server, so the raw credential stays
    // out of reverse-proxy and access logs and out of Referer headers —
    // where a query parameter would have put it for the token's whole life
    // (a day for an admin reset, a week for a welcome link).
    vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: true })
    vi.mocked(api.auth.resetPassword).mockResolvedValue(undefined)
    const user = userEvent.setup()
    renderAt('#token=from-the-fragment')

    await user.type(await screen.findByLabelText(/^New password$/i), 'a-brand-new-password')
    await user.type(screen.getByLabelText(/^Confirm new password$/i), 'a-brand-new-password')
    await user.click(screen.getByRole('button', { name: /set new password/i }))

    expect(api.auth.resetPassword).toHaveBeenCalledWith(
      'from-the-fragment', 'a-brand-new-password'
    )
  })

  it('ignores a token in the query string', async () => {
    // Only the fragment is read. A query parameter would have put the raw
    // credential in every request log, so a link shaped that way is not one
    // this app issues and must not be honoured.
    vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: true })
    renderAt('?token=query-token')

    expect(await screen.findByText(/missing its token/i)).toBeInTheDocument()
    expect(screen.queryByLabelText(/^New password$/i)).not.toBeInTheDocument()
    expect(api.auth.resetPassword).not.toHaveBeenCalled()
  })

  it('reports a link with no token rather than showing a form that cannot work', async () => {
    vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: true })
    renderAt('')

    expect(await screen.findByText(/missing its token/i)).toBeInTheDocument()
    expect(screen.queryByLabelText(/^New password$/i)).not.toBeInTheDocument()
  })

  it('submits the token with the new password and confirms success', async () => {
    vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: true })
    vi.mocked(api.auth.resetPassword).mockResolvedValue(undefined)
    const user = userEvent.setup()
    renderAt('#token=abc123')

    await user.type(await screen.findByLabelText(/^New password$/i), 'a-brand-new-password')
    await user.type(screen.getByLabelText(/^Confirm new password$/i), 'a-brand-new-password')
    await user.click(screen.getByRole('button', { name: /set new password/i }))

    expect(api.auth.resetPassword).toHaveBeenCalledWith('abc123', 'a-brand-new-password')
    expect(await screen.findByText(/password has been updated/i)).toBeInTheDocument()
  })

  it('will not submit when the two passwords differ', async () => {
    vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: true })
    const user = userEvent.setup()
    renderAt('#token=abc123')

    await user.type(await screen.findByLabelText(/^New password$/i), 'a-brand-new-password')
    await user.type(screen.getByLabelText(/^Confirm new password$/i), 'a-different-password')

    expect(screen.getByText(/don't match/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /set new password/i })).toBeDisabled()
    expect(api.auth.resetPassword).not.toHaveBeenCalled()
  })

  it('will not submit a password below the minimum length', async () => {
    vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: true })
    const user = userEvent.setup()
    renderAt('#token=abc123')

    await user.type(await screen.findByLabelText(/^New password$/i), 'short')
    await user.type(screen.getByLabelText(/^Confirm new password$/i), 'short')

    // The intro paragraph also mentions the minimum, so match the hint's
    // own wording rather than the shared phrase.
    expect(screen.getByText(/Must be at least 12 characters/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /set new password/i })).toBeDisabled()
    expect(api.auth.resetPassword).not.toHaveBeenCalled()
  })

  it('does not treat six emoji as 12 characters', async () => {
    // String.prototype.length counts UTF-16 code units — each emoji
    // outside the Basic Multilingual Plane is a surrogate pair, so six
    // emoji report length 12. The backend's Pydantic min_length=12
    // counts Unicode code points (Python's len()), which sees 6 and
    // rejects. Six emoji must still be treated as too short here, or
    // the form lets the user submit something the API then 422s.
    vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: true })
    const user = userEvent.setup()
    renderAt('#token=abc123')

    const sixEmoji = '😀😀😀😀😀😀'
    expect(sixEmoji.length).toBe(12)

    await user.type(await screen.findByLabelText(/^New password$/i), sixEmoji)
    await user.type(screen.getByLabelText(/^Confirm new password$/i), sixEmoji)

    expect(screen.getByText(/Must be at least 12 characters/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /set new password/i })).toBeDisabled()
    expect(api.auth.resetPassword).not.toHaveBeenCalled()
  })

  it('does not treat 40 accented characters as a submittable-length password', async () => {
    // bcrypt hashes only the first 72 *bytes* of its input, and the
    // backend's ResetPasswordRequest.new_password validator
    // (_reject_password_over_bcrypt_limit) rejects anything past that with
    // a 422. 40 "é" characters is 40 Unicode code points — past the
    // 12-character minimum, and not caught by codePointLength — but 80
    // UTF-8 bytes, past the 72-byte limit. Without a byte-length check
    // here, this value looked like an ordinary long password and was
    // submitted, only to be rejected by the API with no explanation shown
    // in this form.
    vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: true })
    const user = userEvent.setup()
    renderAt('#token=abc123')

    const fortyAccented = 'é'.repeat(40)
    await user.type(await screen.findByLabelText(/^New password$/i), fortyAccented)
    await user.type(screen.getByLabelText(/^Confirm new password$/i), fortyAccented)

    expect(screen.getByText(/too long/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /set new password/i })).toBeDisabled()
    expect(api.auth.resetPassword).not.toHaveBeenCalled()
  })

  it('surfaces a rejected token instead of claiming success', async () => {
    vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: true })
    vi.mocked(api.auth.resetPassword).mockRejectedValue(
      new Error('This reset link is invalid or has expired')
    )
    const user = userEvent.setup()
    renderAt('#token=stale')

    await user.type(await screen.findByLabelText(/^New password$/i), 'a-brand-new-password')
    await user.type(screen.getByLabelText(/^Confirm new password$/i), 'a-brand-new-password')
    await user.click(screen.getByRole('button', { name: /set new password/i }))

    expect(await screen.findByText(/invalid or has expired/i)).toBeInTheDocument()
    expect(screen.queryByText(/password has been updated/i)).not.toBeInTheDocument()
  })

  it('preserves the existing history state when stripping the token', async () => {
    // BrowserRouter's own history implementation stores its bookkeeping in
    // window.history.state — { usr, key, idx, masked? }, where idx is the
    // router's position in the history stack — and reads it back on every
    // browser back/forward event to compute how far the user navigated.
    // Passing `null` as the state argument to replaceState (as an earlier
    // version of this effect did) discards that object outright, so the
    // very next back/forward event would desynchronize the router's
    // internally tracked index from the real history position. Confirmed
    // directly by replaying react-router's own getIndex()/handlePop() logic
    // against a `replaceState(null, ...)` call.
    //
    // This test uses MemoryRouter like its siblings above (the component
    // itself is router-agnostic — it calls window.history.replaceState
    // directly, not anything router-provided). The effect under test guards
    // on `window.location.hash` specifically (not the router's own
    // location), which jsdom defaults to empty — so the hash has to be set
    // on the real `window.location` too, or the effect's guard skips
    // entirely and this test would pass vacuously regardless of whether the
    // fix is correct. Confirmed directly: with only MemoryRouter's
    // initialEntries set (no real window.location.hash), the effect never
    // ran and window.history.state was trivially left untouched either way.
    const routerOwnedState = { usr: null, key: 'abc123', idx: 3 }
    window.history.replaceState(
      routerOwnedState, '', `${window.location.pathname}#token=abc123`
    )
    expect(window.location.hash).toBe('#token=abc123') // guard the premise

    vi.mocked(api.auth.passwordResetConfig).mockResolvedValue({ self_service_enabled: true })
    renderAt('#token=abc123')

    await waitFor(() => expect(window.location.hash).toBe(''))
    expect(window.history.state).toEqual(routerOwnedState)
  })
})

// ── Settings toggle gate ──────────────────────────────────────────────────────

describe('SystemSettings — self-service reset toggle', () => {
  const toggle = () => screen.getByLabelText(/reset their own password/i)

  // Readiness now comes from the backend's own validation contract
  // (GET /system-settings/password-reset-readiness), not a frontend
  // re-derivation from smtp_host/app_base_url alone — these tests drive
  // it explicitly per scenario rather than relying on this page to guess.
  const notReady = (...reasons: string[]) =>
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({ ready: false, reasons })
  const ready = () =>
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({ ready: true, reasons: [] })

  // Most tests below configure both smtp_host and app_base_url and are
  // exercising something other than readiness derivation itself (field
  // locking, save payload shape) — default to ready() so they don't each
  // need to restate it, and override with notReady() in the few that are
  // specifically testing an unready state.
  beforeEach(() => { ready() })

  it('is disabled with an explanation when no SMTP host is set', async () => {
    notReady('Requires an SMTP host — there is no way to deliver a reset link without one.')
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: '', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    render(<MemoryRouter><SystemSettings /></MemoryRouter>)

    await waitFor(() => expect(toggle()).toBeDisabled())
    expect(screen.getByText(/requires an SMTP host/i)).toBeInTheDocument()
  })

  it('says the flow is inactive when SMTP was cleared with the flag left on', async () => {
    // The backend re-checks smtp_host at read time, so a saved `true` with no
    // SMTP host means the flow is off — a checked-but-disabled box alone
    // would imply the opposite.
    notReady('Requires an SMTP host — there is no way to deliver a reset link without one.')
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: '', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'self_service_password_reset', value: 'true', value_type: 'bool', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    render(<MemoryRouter><SystemSettings /></MemoryRouter>)

    expect(await screen.findByText(/Inactive — Requires an SMTP host/i)).toBeInTheDocument()
  })

  it('stays disabled with SMTP but no App Base URL', async () => {
    // The backend rejects enabling without both, so the toggle waits for
    // both rather than sending the admin into a 400. A link needs a way to
    // be sent *and* somewhere to point.
    notReady('Requires the App Base URL — reset links have to point at this deployment.')
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: '', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    render(<MemoryRouter><SystemSettings /></MemoryRouter>)

    await waitFor(() => expect(toggle()).toBeDisabled())
    expect(screen.getByText(/Requires the App Base URL/i)).toBeInTheDocument()
  })

  it('is enabled once an SMTP host is configured', async () => {
    ready()
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    render(<MemoryRouter><SystemSettings /></MemoryRouter>)

    await waitFor(() => expect(toggle()).toBeEnabled())
  })

  it('can be switched off when SMTP is empty', async () => {
    // Disabling a *checked* box when SMTP is cleared traps the admin: the
    // form still submits it as enabled, the save is rejected, and there is
    // no control left to fix it with. Only turning it ON needs a host.
    // Turning it off here is a genuine transition (was true, saved as
    // false), so it triggers the token-revocation confirm() prompt.
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    notReady('Requires an SMTP host — there is no way to deliver a reset link without one.')
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: '', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'self_service_password_reset', value: 'true', value_type: 'bool', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    const user = userEvent.setup()
    render(<MemoryRouter><SystemSettings /></MemoryRouter>)

    await waitFor(() => expect(toggle()).toBeChecked())
    expect(toggle()).toBeEnabled()

    await user.click(toggle())
    expect(toggle()).not.toBeChecked()

    await user.click(screen.getByRole('button', { name: /^Save$/i }))
    await waitFor(() => expect(api.systemSettings.update).toHaveBeenCalled())
    expect(
      vi.mocked(api.systemSettings.update).mock.calls[0][0]['self_service_password_reset']
    ).toBe('false')
  })

  it('leaves the SMTP host editable while self-service reset is on, and saves a changed value in the same PATCH', async () => {
    // Not locked while the toggle is on: the backend validates the
    // *effective* (post-PATCH) value of both keys together
    // (patch_settings' _effective()), so replacing this with another valid
    // host in the same save that keeps the feature on is explicitly
    // supported server-side. Locking it forced disabling the feature first
    // just to rotate mail providers — and disabling revokes every
    // outstanding reset/welcome link, an unrelated and unrecoverable side
    // effect of what should be a one-field change.
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'self_service_password_reset', value: 'true', value_type: 'bool', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    const user = userEvent.setup()
    render(<MemoryRouter><SystemSettings /></MemoryRouter>)

    const smtp = await screen.findByLabelText(/SMTP Host/i)
    await waitFor(() => expect(smtp).not.toHaveAttribute('readonly'))

    await user.clear(smtp)
    await user.type(smtp, 'new.smtp.example.com')
    await user.click(screen.getByRole('button', { name: /^Save$/i }))

    await waitFor(() => expect(api.systemSettings.update).toHaveBeenCalled())
    const sent = vi.mocked(api.systemSettings.update).mock.calls[0][0]
    expect(sent['smtp_host']).toBe('new.smtp.example.com')
    expect(sent['self_service_password_reset']).toBe('true')
  })

  it('sends a cleared SMTP host together with turning the toggle off', async () => {
    // Both a genuine toggle-off and a genuine smtp_host clear — triggers
    // the token-revocation confirm() prompt.
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'self_service_password_reset', value: 'true', value_type: 'bool', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    const user = userEvent.setup()
    render(<MemoryRouter><SystemSettings /></MemoryRouter>)

    await waitFor(() => expect(toggle()).toBeChecked())
    await user.click(toggle())

    const smtp = await screen.findByLabelText(/SMTP Host/i)
    await user.clear(smtp)
    await user.click(screen.getByRole('button', { name: /^Save$/i }))

    await waitFor(() => expect(api.systemSettings.update).toHaveBeenCalled())
    const sent = vi.mocked(api.systemSettings.update).mock.calls[0][0]
    expect(sent['smtp_host']).toBeNull()
    expect(sent['self_service_password_reset']).toBe('false')
  })

  it('leaves the App Base URL editable while self-service reset is on, and saves a changed value in the same PATCH', async () => {
    // Unlike SMTP Host above, this field is not locked while the toggle is
    // on: the backend validates the *effective* (post-PATCH) value of both
    // keys together (patch_settings' _effective()), so replacing this with
    // another valid URL in the same save that keeps the feature on is
    // explicitly supported server-side. Locking it forced disabling the
    // feature first just to move the deployment to a new address — and
    // disabling revokes every outstanding reset link, an unrelated and
    // unrecoverable side effect of what should be a one-field change.
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'self_service_password_reset', value: 'true', value_type: 'bool', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    const user = userEvent.setup()
    render(<MemoryRouter><SystemSettings /></MemoryRouter>)

    const baseUrl = await screen.findByLabelText(/App Base URL/i)
    await waitFor(() => expect(baseUrl).not.toHaveAttribute('readonly'))

    await user.clear(baseUrl)
    await user.type(baseUrl, 'https://new.example.com')
    await user.click(screen.getByRole('button', { name: /^Save$/i }))

    await waitFor(() => expect(api.systemSettings.update).toHaveBeenCalled())
    const sent = vi.mocked(api.systemSettings.update).mock.calls[0][0]
    expect(sent['app_base_url']).toBe('https://new.example.com')
    expect(sent['self_service_password_reset']).toBe('true')
  })

  it('leaves the SMTP host editable when self-service reset is off', async () => {
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'self_service_password_reset', value: 'false', value_type: 'bool', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    render(<MemoryRouter><SystemSettings /></MemoryRouter>)

    const smtp = await screen.findByLabelText(/SMTP Host/i)
    expect(smtp).not.toHaveAttribute('readonly')
  })

  it('still refuses to switch on without an SMTP host', async () => {
    notReady('Requires an SMTP host — there is no way to deliver a reset link without one.')
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: '', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'self_service_password_reset', value: 'false', value_type: 'bool', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    render(<MemoryRouter><SystemSettings /></MemoryRouter>)

    await waitFor(() => expect(toggle()).toBeDisabled())
    expect(toggle()).not.toBeChecked()
  })

  // The backend accepts "true"/"1"/"yes"/"on" (any casing) and only
  // canonicalises on write, so a row stored before that — or written straight
  // to the database — can hold any of them. Matching only "true" here showed
  // such a setting as off *and* let the save loop overwrite it with "false",
  // silently disabling a live security feature during an unrelated edit.
  for (const stored of ['yes', 'on', '1', 'TRUE']) {
    it(`reads a value stored as "${stored}" as enabled`, async () => {
      vi.mocked(api.systemSettings.list).mockResolvedValue([
        { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
        { key: 'self_service_password_reset', value: stored, value_type: 'bool', updated_at: null, updated_by_id: null, is_default: false },
      ] as any)
      render(<MemoryRouter><SystemSettings /></MemoryRouter>)

      await waitFor(() => expect(toggle()).toBeChecked())
    })

    it(`does not silently disable a value stored as "${stored}" on an unrelated save`, async () => {
      vi.mocked(api.systemSettings.list).mockResolvedValue([
        { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
        { key: 'self_service_password_reset', value: stored, value_type: 'bool', updated_at: null, updated_by_id: null, is_default: false },
      ] as any)
      const user = userEvent.setup()
      render(<MemoryRouter><SystemSettings /></MemoryRouter>)

      await waitFor(() => expect(toggle()).toBeChecked())
      await user.click(screen.getByRole('button', { name: /^Save$/i }))

      await waitFor(() => expect(api.systemSettings.update).toHaveBeenCalled())
      const sent = vi.mocked(api.systemSettings.update).mock.calls[0][0]
      expect(sent['self_service_password_reset']).toBe('true')
    })
  }

  it('saves the toggle as an explicit boolean string', async () => {
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'self_service_password_reset', value: 'false', value_type: 'bool', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    const user = userEvent.setup()
    render(<MemoryRouter><SystemSettings /></MemoryRouter>)

    await waitFor(() => expect(toggle()).toBeEnabled())
    await user.click(toggle())
    await user.click(screen.getByRole('button', { name: /^Save$/i }))

    await waitFor(() => expect(api.systemSettings.update).toHaveBeenCalled())
    const updates = vi.mocked(api.systemSettings.update).mock.calls[0][0]
    // "false" rather than null — an unchecked box is a saved false, not a
    // cleared row, so it must not go through the empty-string-to-null rule.
    expect(updates['self_service_password_reset']).toBe('true')
  })

  it('sends false rather than null when the toggle is turned off', async () => {
    // Genuine toggle-off transition — triggers the token-revocation
    // confirm() prompt.
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'self_service_password_reset', value: 'true', value_type: 'bool', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    const user = userEvent.setup()
    render(<MemoryRouter><SystemSettings /></MemoryRouter>)

    await waitFor(() => expect(toggle()).toBeChecked())
    await user.click(toggle())
    await user.click(screen.getByRole('button', { name: /^Save$/i }))

    await waitFor(() => expect(api.systemSettings.update).toHaveBeenCalled())
    const updates = vi.mocked(api.systemSettings.update).mock.calls[0][0]
    expect(updates['self_service_password_reset']).toBe('false')
  })
})
