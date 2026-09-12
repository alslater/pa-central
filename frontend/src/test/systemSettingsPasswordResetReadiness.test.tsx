import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { vi, beforeEach, describe, it, expect } from 'vitest'

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}))

vi.mock('@/lib/api', () => ({
  api: {
    systemSettings: { list: vi.fn(), update: vi.fn(), passwordResetReadiness: vi.fn() },
  },
}))

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import SystemSettings from '@/pages/SystemSettings'

const mockAdmin = { id: 1, email: 'admin@example.com', display_name: 'Admin', role: 'admin' as const }

function renderPage() {
  return render(<MemoryRouter><SystemSettings /></MemoryRouter>)
}

const smtpConfiguredRows = [
  { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: '2026-09-01T00:00:00Z', updated_by_id: 1, is_default: false },
  { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: '2026-09-01T00:00:00Z', updated_by_id: 1, is_default: false },
]

beforeEach(() => {
  vi.mocked(useAuth).mockReturnValue({ user: mockAdmin } as any)
  vi.mocked(api.systemSettings.update).mockResolvedValue([])
})

describe('SystemSettings — password reset readiness comes from the backend', () => {
  // Previously this page re-derived "can this be enabled" from only
  // smtp_host/app_base_url being non-empty, which disagreed with the
  // backend's real validation contract (port range, TLS mode, From
  // address shape, App Base URL scheme/structure). These tests drive the
  // checkbox purely off the mocked readiness response, proving the page
  // no longer computes that judgment itself.

  it('disables the checkbox and shows the backend reason when not ready, even though smtp_host and app_base_url both look filled in', async () => {
    vi.mocked(api.systemSettings.list).mockResolvedValue(smtpConfiguredRows as any)
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({
      ready: false,
      reasons: ['SMTP port must be a usable value (1-65535).'],
    })

    renderPage()

    const checkbox = await screen.findByLabelText(/Allow users to reset their own password by email/i)
    expect(checkbox).toBeDisabled()
    expect(await screen.findByText(/SMTP port must be a usable value/i)).toBeInTheDocument()
  })

  it('enables the checkbox when the backend reports ready, with no reasons shown', async () => {
    vi.mocked(api.systemSettings.list).mockResolvedValue(smtpConfiguredRows as any)
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({ ready: true, reasons: [] })

    renderPage()

    const checkbox = await screen.findByLabelText(/Allow users to reset their own password by email/i)
    expect(checkbox).toBeEnabled()
    expect(await screen.findByText(/Forgot password/i)).toBeInTheDocument()
  })

  it('keeps a checked box operable (not disabled) and explains it is inactive when readiness turns false while the flag is on', async () => {
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      ...smtpConfiguredRows,
      { key: 'self_service_password_reset', value: 'true', value_type: 'bool', updated_at: '2026-09-01T00:00:00Z', updated_by_id: 1, is_default: false },
    ] as any)
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({
      ready: false,
      reasons: ['App Base URL is not a usable public address.'],
    })

    renderPage()

    const checkbox = await screen.findByLabelText(/Allow users to reset their own password by email/i)
    expect(checkbox).toBeChecked()
    expect(checkbox).toBeEnabled()
    expect(await screen.findByText(/Inactive/i)).toBeInTheDocument()
    expect(screen.getByText(/App Base URL is not a usable public address/i)).toBeInTheDocument()
  })

  it('re-fetches readiness after a successful save, so fixing the underlying value updates the checkbox without a reload', async () => {
    const user = userEvent.setup()
    vi.mocked(api.systemSettings.list).mockResolvedValue(smtpConfiguredRows as any)
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({
      ready: false,
      reasons: ['SMTP port must be a usable value (1-65535).'],
    })

    renderPage()

    const checkboxBefore = await screen.findByLabelText(/Allow users to reset their own password by email/i)
    expect(checkboxBefore).toBeDisabled()

    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({ ready: true, reasons: [] })
    await user.click(screen.getByRole('button', { name: /^save$/i }))

    expect(api.systemSettings.update).toHaveBeenCalledTimes(1)
    const checkboxAfter = await screen.findByLabelText(/Allow users to reset their own password by email/i)
    expect(checkboxAfter).toBeEnabled()
  })
})

describe('SystemSettings — an unsaved edit to a dependency field cannot act on stale readiness', () => {
  // Readiness is only ever fetched on load and after a successful save —
  // never on every keystroke — so it reflects the last *persisted* state,
  // not the current draft. Filling in a previously-missing field left the
  // toggle disabled (readiness still says "not ready" for the old, empty
  // value); clearing a previously-valid field left it enabled (readiness
  // still says "ready" for the old, valid value) and let a save reach the
  // backend with a combination it would reject. Both directions must be
  // caught client-side by treating a dependency field's unsaved edit as
  // "readiness doesn't apply until this is saved," not by re-deriving
  // validity from the field values.

  it('keeps the checkbox disabled while a fix to a missing field is unsaved, even though the field now looks correct', async () => {
    const user = userEvent.setup()
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: '', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({
      ready: false,
      reasons: ['Requires an SMTP host — there is no way to deliver a reset link without one.'],
    })

    renderPage()

    const smtpInput = await screen.findByLabelText(/SMTP Host/i)
    await user.type(smtpInput, 'smtp.example.com')

    const checkbox = screen.getByLabelText(/Allow users to reset their own password by email/i)
    expect(checkbox).toBeDisabled()
    expect(screen.getByText(/Save your SMTP and App Base URL changes/i)).toBeInTheDocument()
  })

  it('disables enabling once a valid field is cleared in the draft, even though the last-fetched readiness still says ready', async () => {
    const user = userEvent.setup()
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({ ready: true, reasons: [] })

    renderPage()

    const checkboxBefore = await screen.findByLabelText(/Allow users to reset their own password by email/i)
    expect(checkboxBefore).toBeEnabled()

    const smtpInput = screen.getByLabelText(/SMTP Host/i)
    await user.clear(smtpInput)

    expect(checkboxBefore).toBeDisabled()
    expect(screen.getByText(/Save your SMTP and App Base URL changes/i)).toBeInTheDocument()
  })

  it('warns instead of showing the normal message when a dependency is cleared while the flag is already on and checked', async () => {
    const user = userEvent.setup()
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'self_service_password_reset', value: 'true', value_type: 'bool', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({ ready: true, reasons: [] })

    renderPage()

    const checkbox = await screen.findByLabelText(/Allow users to reset their own password by email/i)
    expect(checkbox).toBeChecked()

    const smtpInput = screen.getByLabelText(/SMTP Host/i)
    await user.clear(smtpInput)

    // Still checked and still operable — clearing a field must not force
    // the admin to untick it — but the message must say a save is needed
    // to confirm, not the normal "Adds a Forgot password? link" text.
    expect(checkbox).toBeChecked()
    expect(checkbox).toBeEnabled()
    expect(screen.getByText(/Unsaved changes.*save them to confirm/i)).toBeInTheDocument()
    expect(screen.queryByText(/Adds a "Forgot password\?" link/i)).not.toBeInTheDocument()
  })

  it('clears the warning once the edit is saved and readiness is re-fetched', async () => {
    const user = userEvent.setup()
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({ ready: true, reasons: [] })
    vi.mocked(api.systemSettings.update).mockResolvedValue([
      { key: 'smtp_host', value: 'new.smtp.example.com', value_type: 'string', updated_at: '2026-09-11T00:00:00Z', updated_by_id: 1, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: '2026-09-11T00:00:00Z', updated_by_id: 1, is_default: false },
    ] as any)

    renderPage()

    const smtpInput = await screen.findByLabelText(/SMTP Host/i)
    await user.clear(smtpInput)
    await user.type(smtpInput, 'new.smtp.example.com')

    const checkbox = screen.getByLabelText(/Allow users to reset their own password by email/i)
    expect(checkbox).toBeDisabled()

    await user.click(screen.getByRole('button', { name: /^save$/i }))

    await screen.findByText(/Forgot password/i)
    expect(checkbox).toBeEnabled()
  })

  it('does not re-enable the toggle the instant a save completes, before the refreshed readiness arrives', async () => {
    // applyRows() (called synchronously once the save's response lands)
    // clears hasUnsavedDependencyEdits immediately — but the readiness
    // fetch save() also kicks off is asynchronous and still reflects the
    // *previous* persisted state until it resolves. Without invalidating
    // readiness first, canEnableReset would combine "no unsaved edits"
    // (true, as of applyRows) with the stale pre-save readiness verdict
    // (which said ready) for the whole gap — reproduced directly by
    // holding the second passwordResetReadiness call open with a promise
    // that is never resolved during the assertion below.
    //
    // Clearing smtp_host here is itself a genuine token-revoking
    // transition (see the "warns about token revocation" describe block
    // below), so this save legitimately triggers a confirm() prompt —
    // confirmed here to isolate this test's own concern.
    const user = userEvent.setup()
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    // First call: the page's initial load. Second call: fired by save()
    // below, and deliberately left pending for the duration of this test.
    vi.mocked(api.systemSettings.passwordResetReadiness)
      .mockResolvedValueOnce({ ready: true, reasons: [] })
      .mockImplementationOnce(() => new Promise(() => {}))
    vi.mocked(api.systemSettings.update).mockResolvedValue([
      { key: 'smtp_host', value: '', value_type: 'string', updated_at: '2026-09-11T00:00:00Z', updated_by_id: 1, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: '2026-09-11T00:00:00Z', updated_by_id: 1, is_default: false },
    ] as any)

    renderPage()

    const smtpInput = await screen.findByLabelText(/SMTP Host/i)
    await user.clear(smtpInput)

    const checkbox = screen.getByLabelText(/Allow users to reset their own password by email/i)
    expect(checkbox).toBeDisabled()

    await user.click(screen.getByRole('button', { name: /^save$/i }))
    await screen.findByText(/Settings saved/i)

    expect(checkbox).toBeDisabled()
  })

  it('stays disabled indefinitely if the post-save readiness refresh fails', async () => {
    // Clearing smtp_host is a genuine token-revoking transition (see the
    // "warns about token revocation" describe block below); confirmed
    // here to isolate this test's own concern.
    const user = userEvent.setup()
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    vi.mocked(api.systemSettings.passwordResetReadiness)
      .mockResolvedValueOnce({ ready: true, reasons: [] })
      .mockRejectedValueOnce(new Error('network error'))
    vi.mocked(api.systemSettings.update).mockResolvedValue([
      { key: 'smtp_host', value: '', value_type: 'string', updated_at: '2026-09-11T00:00:00Z', updated_by_id: 1, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: '2026-09-11T00:00:00Z', updated_by_id: 1, is_default: false },
    ] as any)

    renderPage()

    const smtpInput = await screen.findByLabelText(/SMTP Host/i)
    await user.clear(smtpInput)

    const checkbox = screen.getByLabelText(/Allow users to reset their own password by email/i)
    expect(checkbox).toBeDisabled()

    await user.click(screen.getByRole('button', { name: /^save$/i }))
    await screen.findByText(/network error/i)

    expect(checkbox).toBeDisabled()
  })

  it('does not let a slow mount-time readiness response overwrite a fresher post-save one', async () => {
    // loadReadiness runs once on mount and again after a successful save,
    // and nothing guarantees those two requests resolve in the order they
    // were issued. If the mount-time fetch is still in flight when a save
    // completes and its own (fresher) readiness fetch resolves first, the
    // late-arriving mount response must not be allowed to clobber the
    // fresher verdict just because it happens to resolve second.
    //
    // Reproduced directly: without sequencing, resolving the held-open
    // mount fetch with an older ready:true after a post-save ready:false
    // had already landed left the checkbox looking enableable again,
    // indefinitely, since nothing re-fetches after this.
    const user = userEvent.setup()
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    // The flag itself stays checked and unedited across the save — only an
    // unrelated field (app_base_url) changes — so canEnableReset depends
    // entirely on the readiness verdict here, not on hasUnsavedDependencyEdits.
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'self_service_password_reset', value: 'true', value_type: 'bool', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)

    let resolveMountReadiness: (v: { ready: boolean; reasons: string[] }) => void = () => {}
    const mountReadiness = new Promise<{ ready: boolean; reasons: string[] }>(res => {
      resolveMountReadiness = res
    })
    // First call: the page's initial mount, deliberately left pending.
    // Second call: fired by save() below, and resolves immediately with the
    // fresh, correct (not-ready) verdict. A distinct, identifiable reason
    // string lets the assertions below confirm this exact response landed
    // and is still showing, rather than a stale/default value that happens
    // to look the same.
    vi.mocked(api.systemSettings.passwordResetReadiness)
      .mockImplementationOnce(() => mountReadiness)
      .mockResolvedValueOnce({ ready: false, reasons: ['fresh-post-save-verdict'] })
    vi.mocked(api.systemSettings.update).mockResolvedValue([
      { key: 'self_service_password_reset', value: 'true', value_type: 'bool', updated_at: '2026-09-11T00:00:00Z', updated_by_id: 1, is_default: false },
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: '2026-09-11T00:00:00Z', updated_by_id: 1, is_default: false },
      { key: 'app_base_url', value: 'https://new.pa.example.com', value_type: 'string', updated_at: '2026-09-11T00:00:00Z', updated_by_id: 1, is_default: false },
    ] as any)

    renderPage()
    const baseUrlInput = await screen.findByLabelText(/App Base URL/i)
    await user.clear(baseUrlInput)
    await user.type(baseUrlInput, 'https://new.pa.example.com')

    await user.click(screen.getByRole('button', { name: /^save$/i }))
    await screen.findByText(/Settings saved/i)
    await screen.findByText(/fresh-post-save-verdict/i)

    // The stale mount-time fetch finally resolves, with a verdict computed
    // before the save ever happened. It must not un-render the fresh
    // not-ready message that's already showing.
    resolveMountReadiness({ ready: true, reasons: [] })
    await waitFor(() => {
      expect(screen.getByText(/fresh-post-save-verdict/i)).toBeInTheDocument()
    })
    expect(screen.queryByText(/Adds a "Forgot password\?" link/i)).not.toBeInTheDocument()
  })

  it('does not let a slow mount-time settings response overwrite a fresher post-save one', async () => {
    // list() has the identical race as passwordResetReadiness() above: it
    // runs once on mount and again after a successful save, and nothing
    // guarantees the mount-time fetch resolves first. If it is still in
    // flight when a save completes — whose own state is applied directly
    // from the update() response, not from a second list() call — the late
    // mount response must not be allowed to clobber that fresher state just
    // because it happens to resolve second.
    //
    // Reproduced directly: without sequencing, resolving a held-open mount
    // list() call with the pre-save snapshot after a save had already
    // applied the post-save one flipped the page straight back to showing
    // the old values, with nothing left to correct it since no further
    // fetch is scheduled.
    const user = userEvent.setup()
    vi.spyOn(window, 'confirm').mockReturnValue(true)

    let resolveMountList: (v: unknown) => void = () => {}
    const mountList = new Promise(res => { resolveMountList = res })
    // First call: the page's initial mount, deliberately left pending.
    // Second call: fired only if something re-calls list() after the
    // mount — save() itself does not; it applies update()'s own response
    // directly — so this exists purely so a stray extra call doesn't hang
    // the test if the implementation changes to also refetch after saving.
    vi.mocked(api.systemSettings.list)
      .mockImplementationOnce(() => mountList as any)
      .mockResolvedValue([
        { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: '2026-09-12T00:00:00Z', updated_by_id: 1, is_default: false },
        { key: 'app_base_url', value: 'https://new.pa.example.com', value_type: 'string', updated_at: '2026-09-12T00:00:00Z', updated_by_id: 1, is_default: false },
      ] as any)
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({ ready: true, reasons: [] })
    vi.mocked(api.systemSettings.update).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: '2026-09-12T00:00:00Z', updated_by_id: 1, is_default: false },
      { key: 'app_base_url', value: 'https://new.pa.example.com', value_type: 'string', updated_at: '2026-09-12T00:00:00Z', updated_by_id: 1, is_default: false },
    ] as any)

    renderPage()
    // The mount list() call never resolves during this render, so the form
    // fields render with their default empty values — the admin can still
    // type into them and save, exactly as this test does.
    const baseUrlInput = await screen.findByLabelText(/App Base URL/i)
    await user.type(baseUrlInput, 'https://new.pa.example.com')
    const smtpInput = screen.getByLabelText(/SMTP Host/i)
    await user.type(smtpInput, 'smtp.example.com')

    await user.click(screen.getByRole('button', { name: /^save$/i }))
    await screen.findByText(/Settings saved/i)
    expect(screen.getByLabelText(/App Base URL/i)).toHaveValue('https://new.pa.example.com')

    // The stale mount-time fetch finally resolves, with the pre-save
    // snapshot (both fields empty). It must not un-render the fresh
    // post-save value already showing.
    resolveMountList([])
    await waitFor(() => {
      expect(screen.getByLabelText(/App Base URL/i)).toHaveValue('https://new.pa.example.com')
    })
    expect(screen.getByLabelText(/SMTP Host/i)).toHaveValue('smtp.example.com')
  })

  it('keeps the toggle disabled while the initial settings request is still pending, even once readiness has already resolved', async () => {
    // The two mount-time requests (list() and passwordResetReadiness()) are
    // independent — nothing ties their resolution order together. If
    // readiness resolves first, settings/savedSettings are both still {}
    // at that point, and hasUnsavedDependencyEdits (which diffs those two
    // objects) sees every dependency key as equal — '' on both sides — and
    // reads as false. Combined with an already-resolved ready:true
    // readiness, canEnableReset would read true from a page that has not
    // actually loaded this account's real settings yet, and an admin could
    // save on the strength of a verdict computed against nothing.
    //
    // settingsLoaded is the fix: canEnableReset requires it, so the toggle
    // stays disabled until list() has genuinely completed at least once,
    // regardless of how fast readiness resolves.
    vi.mocked(api.systemSettings.list).mockImplementation(() => new Promise(() => {}))
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({ ready: true, reasons: [] })

    renderPage()

    const checkbox = await screen.findByLabelText(/Allow users to reset their own password by email/i)
    // list() never resolves in this test at all, so settingsLoaded can
    // never become true — the checkbox staying disabled here is not a
    // timing coincidence, it is the only outcome the fix permits. waitFor
    // (rather than a single synchronous check) still confirms readiness's
    // already-resolved promise has had a genuine chance to apply before
    // this assertion runs.
    await waitFor(() => {
      expect(vi.mocked(api.systemSettings.passwordResetReadiness)).toHaveBeenCalled()
    })
    await waitFor(() => {
      expect(checkbox).toBeDisabled()
    })
    // A second check after further time has passed: without the fix,
    // nothing would ever re-disable a checkbox that read as enableable —
    // this confirms the disabled state is the fix actually gating it, not
    // an artifact of not having waited long enough for something else to
    // flip it.
    await new Promise(r => setTimeout(r, 50))
    expect(checkbox).toBeDisabled()
  })
})

describe('SystemSettings — saving a genuine transition warns about token revocation', () => {
  // patch_settings' turning_off/losing_smtp sweep retires every outstanding
  // reset token system-wide — admin-reset and welcome links included, for
  // every user, not just the "Forgot password?" flow — whenever a save
  // genuinely flips self-service reset from on to off, or genuinely clears
  // a previously-set smtp_host. The page gave no warning before saving,
  // even though this is destructive and can strand a newly invited or
  // admin-reset user who hasn't used their link yet.

  beforeEach(() => {
    vi.spyOn(window, 'confirm').mockClear()
    vi.mocked(api.systemSettings.update).mockClear()
  })

  it('confirms before saving a genuine on-to-off transition, and does not save if cancelled', async () => {
    const user = userEvent.setup()
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'self_service_password_reset', value: 'true', value_type: 'bool', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({ ready: true, reasons: [] })

    renderPage()

    const checkbox = await screen.findByLabelText(/Allow users to reset their own password by email/i)
    await user.click(checkbox)
    await user.click(screen.getByRole('button', { name: /^save$/i }))

    expect(window.confirm).toHaveBeenCalledOnce()
    expect(window.confirm).toHaveBeenCalledWith(expect.stringMatching(/invalidate every outstanding password reset link/i))
    expect(api.systemSettings.update).not.toHaveBeenCalled()
  })

  it('saves after confirming a genuine on-to-off transition', async () => {
    const user = userEvent.setup()
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'self_service_password_reset', value: 'true', value_type: 'bool', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({ ready: true, reasons: [] })
    vi.mocked(api.systemSettings.update).mockResolvedValue([])

    renderPage()

    const checkbox = await screen.findByLabelText(/Allow users to reset their own password by email/i)
    await user.click(checkbox)
    await user.click(screen.getByRole('button', { name: /^save$/i }))

    expect(api.systemSettings.update).toHaveBeenCalledWith(
      expect.objectContaining({ self_service_password_reset: 'false' })
    )
  })

  it('does not confirm when the flag was already off and only an unrelated field changed', async () => {
    const user = userEvent.setup()
    const confirmSpy = vi.spyOn(window, 'confirm')
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'sla_high_days', value: '14', value_type: 'int', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({ ready: true, reasons: [] })
    vi.mocked(api.systemSettings.update).mockResolvedValue([])

    renderPage()

    const slaInput = await screen.findByLabelText(/SLA: High\/Critical \(days\)/i)
    await user.clear(slaInput)
    await user.type(slaInput, '21')
    await user.click(screen.getByRole('button', { name: /^save$/i }))

    expect(confirmSpy).not.toHaveBeenCalled()
    expect(api.systemSettings.update).toHaveBeenCalled()
  })

  it('confirms before saving a genuine smtp_host clear', async () => {
    const user = userEvent.setup()
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({ ready: false, reasons: [] })

    renderPage()

    const smtpInput = await screen.findByLabelText(/SMTP Host/i)
    await user.clear(smtpInput)
    await user.click(screen.getByRole('button', { name: /^save$/i }))

    expect(window.confirm).toHaveBeenCalledOnce()
    expect(api.systemSettings.update).not.toHaveBeenCalled()
  })

  it('does not confirm when smtp_host was already empty', async () => {
    const user = userEvent.setup()
    const confirmSpy = vi.spyOn(window, 'confirm')
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: '', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({ ready: false, reasons: [] })
    vi.mocked(api.systemSettings.update).mockResolvedValue([])

    renderPage()

    await screen.findByLabelText(/SMTP Host/i)
    await user.click(screen.getByRole('button', { name: /^save$/i }))

    expect(confirmSpy).not.toHaveBeenCalled()
  })

  it('confirms before saving a genuine app_base_url change', async () => {
    // Mirrors the backend's own changing_base_url condition
    // (api/system_settings.py): a link already emailed is built against
    // the old app_base_url and stays redeemable regardless of the change
    // (consume_reset_token isn't origin-bound), so changing it retires
    // every outstanding token exactly like turning the feature off does.
    const user = userEvent.setup()
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({ ready: false, reasons: [] })

    renderPage()

    const baseUrlInput = await screen.findByLabelText(/App Base URL/i)
    await user.clear(baseUrlInput)
    await user.type(baseUrlInput, 'https://new.pa.example.com')
    await user.click(screen.getByRole('button', { name: /^save$/i }))

    expect(window.confirm).toHaveBeenCalledOnce()
    expect(api.systemSettings.update).not.toHaveBeenCalled()
  })

  it('does not confirm when resubmitting the same app_base_url', async () => {
    const user = userEvent.setup()
    const confirmSpy = vi.spyOn(window, 'confirm')
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'smtp_host', value: 'smtp.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
      { key: 'app_base_url', value: 'https://pa.example.com', value_type: 'string', updated_at: null, updated_by_id: null, is_default: false },
    ] as any)
    vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({ ready: false, reasons: [] })
    vi.mocked(api.systemSettings.update).mockResolvedValue([])

    renderPage()

    await screen.findByLabelText(/App Base URL/i)
    await user.click(screen.getByRole('button', { name: /^save$/i }))

    expect(confirmSpy).not.toHaveBeenCalled()
  })
})

