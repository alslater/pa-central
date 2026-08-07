/**
 * Users page — inline edit, TOTP reset, and delete flow tests.
 */
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { vi, beforeEach, afterEach, describe, it, expect } from 'vitest'
import type { User } from '@/lib/api'

// ── Module mocks (hoisted) ────────────────────────────────────────────────────

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}))

vi.mock('@/lib/api', () => ({
  api: {
    users: {
      list:      vi.fn(),
      delete:    vi.fn(),
      resetTotp: vi.fn(),
      update:    vi.fn(),
    },
    auth: {
      register: vi.fn(),
    },
  },
}))

// ── Imports (after mocks) ─────────────────────────────────────────────────────

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import Users from '@/pages/Users'

// ── Helpers ────────────────────────────────────────────────────────────────────

const ADMIN: User = {
  id: 1, email: 'admin@example.com', display_name: 'Admin',
  role: 'admin', is_active: true, totp_enabled: false, created_at: '2024-01-01T00:00:00Z',
}

const TARGET: User = {
  id: 2, email: 'bob@example.com', display_name: 'Bob',
  role: 'viewer', is_active: true, totp_enabled: false, created_at: '2024-01-01T00:00:00Z',
}

const TARGET_TOTP: User = {
  ...TARGET, totp_enabled: true,
}

// A second deletable row, so tests can expand one user and delete another.
const OTHER: User = {
  id: 3, email: 'carol@example.com', display_name: 'Carol',
  role: 'viewer', is_active: true, totp_enabled: false, created_at: '2024-01-01T00:00:00Z',
}

// Non-admin signed-in users. TARGET (id 2) is already in the default list, so
// signing in as one of these also covers "cannot act on my own row".
const VIEWER: User = { ...TARGET, role: 'viewer' }
const OPERATOR: User = { ...TARGET, role: 'operator' }
const DEVELOPER: User = { ...TARGET, role: 'developer' }

function setup({ totpEnabled = false, withOther = false, as = ADMIN } = {}) {
  vi.mocked(useAuth).mockReturnValue({
    user: as, loading: false,
    login: vi.fn(), completeTotp: vi.fn(), logout: vi.fn(),
  })
  const list = [ADMIN, totpEnabled ? TARGET_TOTP : TARGET]
  if (withOther) list.push(OTHER)
  vi.mocked(api.users.list).mockResolvedValue(list)
  // Unexpected fetch calls throw so they surface as real test failures rather
  // than silently becoming "Unauthorized" UI noise.
  vi.stubGlobal('fetch', vi.fn().mockImplementation((url: unknown) => {
    throw new Error(`Unexpected fetch to ${url} — mock api methods instead`)
  }))
  return userEvent.setup()
}

function renderPage() {
  return render(<MemoryRouter><Users /></MemoryRouter>)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Users page — delete flow', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

  it('shows delete button for other users but not for self', async () => {
    setup()
    renderPage()
    await screen.findByText('Bob')
    expect(screen.getByRole('button', { name: /delete bob/i })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /delete admin/i })).not.toBeInTheDocument()
  })

  it('cancel leaves the list unchanged and does not call api.users.delete', async () => {
    const user = setup()
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    renderPage()
    await user.click(await screen.findByRole('button', { name: /delete bob/i }))
    expect(window.confirm).toHaveBeenCalledOnce()
    expect(api.users.delete).not.toHaveBeenCalled()
    expect(screen.getByText('Bob')).toBeInTheDocument()
  })

  it('confirm calls api.users.delete and removes the row', async () => {
    const user = setup()
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    vi.mocked(api.users.delete).mockResolvedValue(undefined)
    renderPage()
    await user.click(await screen.findByRole('button', { name: /delete bob/i }))
    expect(api.users.delete).toHaveBeenCalledWith(TARGET.id)
    // Await the toast first: the row removal is a state update that lands after
    // the awaited delete resolves, so a bare queryByText could pass merely
    // because React had not re-rendered yet.
    expect(await screen.findByText(/user deleted/i)).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText('Bob')).not.toBeInTheDocument())
  })

  it('deleting a different user leaves another row\'s edit panel open', async () => {
    const user = setup({ withOther: true })
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    vi.mocked(api.users.delete).mockResolvedValue(undefined)
    renderPage()
    // Expand Bob, then delete Carol — Bob's unsaved edits must survive.
    await user.click(await screen.findByText('Bob'))
    await user.selectOptions(await screen.findByRole('combobox', { name: /role/i }), 'operator')
    await user.click(screen.getByRole('button', { name: /delete carol/i }))
    expect(api.users.delete).toHaveBeenCalledWith(OTHER.id)
    // Wait for the delete to settle before asserting on the resulting UI —
    // otherwise the panel checks below could pass against pre-delete state.
    expect(await screen.findByText(/user deleted/i)).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText('Carol')).not.toBeInTheDocument())
    expect(screen.getByRole('button', { name: /^discard$/i })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: /role/i })).toHaveValue('operator')
  })

  it('deleting the expanded user collapses its panel', async () => {
    const user = setup({ withOther: true })
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    vi.mocked(api.users.delete).mockResolvedValue(undefined)
    renderPage()
    await user.click(await screen.findByText('Bob'))
    await screen.findByRole('button', { name: /^discard$/i })
    await user.click(screen.getByRole('button', { name: /delete bob/i }))
    // Both assertions here are negative, so without waiting for a positive
    // signal first they would also pass against a not-yet-updated DOM.
    expect(await screen.findByText(/user deleted/i)).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText('Bob')).not.toBeInTheDocument())
    expect(screen.queryByRole('button', { name: /^discard$/i })).not.toBeInTheDocument()
  })

  it('api error shows toast and keeps the row', async () => {
    const user = setup()
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    vi.mocked(api.users.delete).mockRejectedValue(new Error('Server error'))
    renderPage()
    await user.click(await screen.findByRole('button', { name: /delete bob/i }))
    expect(await screen.findByText(/server error/i)).toBeInTheDocument()
    expect(screen.getByText('Bob')).toBeInTheDocument()
  })
})

// ── Non-admin authorization ───────────────────────────────────────────────────

describe('Users page — non-admin cannot manage users', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

  // Every non-admin role is gated identically by `isAdmin`, so each one is
  // checked rather than assuming viewer stands in for the rest.
  const NON_ADMINS: [string, User][] = [
    ['viewer', VIEWER],
    ['operator', OPERATOR],
    ['developer', DEVELOPER],
  ]

  it.each(NON_ADMINS)('%s sees no delete buttons and no Add user action', async (_role, as) => {
    setup({ as, withOther: true })
    renderPage()
    await screen.findByText('Admin')
    expect(screen.queryByRole('button', { name: /delete/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /add user/i })).not.toBeInTheDocument()
  })

  it.each(NON_ADMINS)('%s cannot expand another user\'s row', async (_role, as) => {
    const user = setup({ as, withOther: true })
    renderPage()
    await user.click(await screen.findByText('Carol'))
    expect(screen.queryByRole('button', { name: /^discard$/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('combobox', { name: /role/i })).not.toBeInTheDocument()
  })

  it.each(NON_ADMINS)('%s cannot expand their own row', async (_role, as) => {
    const user = setup({ as })
    renderPage()
    await user.click(await screen.findByText('Bob'))
    expect(screen.queryByRole('button', { name: /^discard$/i })).not.toBeInTheDocument()
  })

  it('viewer clicking a row never calls the update or delete APIs', async () => {
    const user = setup({ as: VIEWER, withOther: true })
    renderPage()
    await user.click(await screen.findByText('Carol'))
    await user.click(screen.getByText('Admin'))
    expect(api.users.update).not.toHaveBeenCalled()
    expect(api.users.delete).not.toHaveBeenCalled()
    expect(api.users.resetTotp).not.toHaveBeenCalled()
  })
})

// ── Expanded edit panel ───────────────────────────────────────────────────────

describe('Users page — expanded edit panel', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

  it('clicking another user row expands the edit panel', async () => {
    const user = setup()
    renderPage()
    await user.click(await screen.findByText('Bob'))
    expect(screen.getByRole('combobox', { name: /role/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^save$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^discard$/i })).toBeInTheDocument()
  })

  it('clicking the same row again collapses the panel', async () => {
    const user = setup()
    renderPage()
    await user.click(await screen.findByText('Bob'))
    await screen.findByRole('button', { name: /^discard$/i })
    await user.click(screen.getByText('Bob'))
    expect(screen.queryByRole('button', { name: /^discard$/i })).not.toBeInTheDocument()
  })

  it('clicking own row does not expand the panel', async () => {
    const user = setup()
    renderPage()
    await user.click(await screen.findByText('Admin'))
    expect(screen.queryByRole('button', { name: /^discard$/i })).not.toBeInTheDocument()
  })

  it('Discard collapses the panel without calling update', async () => {
    const user = setup()
    renderPage()
    await user.click(await screen.findByText('Bob'))
    await user.click(await screen.findByRole('button', { name: /^discard$/i }))
    expect(api.users.update).not.toHaveBeenCalled()
    expect(screen.queryByRole('button', { name: /^discard$/i })).not.toBeInTheDocument()
  })

  it('Save is disabled when no changes made', async () => {
    const user = setup()
    renderPage()
    await user.click(await screen.findByText('Bob'))
    expect(await screen.findByRole('button', { name: /^save$/i })).toBeDisabled()
  })
})

// ── Prop sync while panel is open ─────────────────────────────────────────────

describe('Users page — edit panel syncs to changed user prop', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

  /** Create a user via the Add modal, which triggers load() and refreshes the list. */
  async function createUserToTriggerReload(user: ReturnType<typeof userEvent.setup>) {
    await user.click(screen.getByRole('button', { name: /add user/i }))
    await user.type(screen.getByLabelText(/display name/i), 'Dave')
    await user.type(screen.getByLabelText(/email/i), 'dave@example.com')
    await user.type(screen.getByLabelText(/password/i), 'password12345')
    await user.click(screen.getByRole('button', { name: /create user/i }))
  }

  it('shows refreshed server state after a list reload', async () => {
    const user = setup()
    vi.mocked(api.auth.register).mockResolvedValue(undefined as never)
    renderPage()
    await user.click(await screen.findByText('Bob'))
    expect(await screen.findByRole('combobox', { name: /role/i })).toHaveValue('viewer')

    // Bob is promoted elsewhere; the refresh returns the new object. A reload
    // flips `loading`, which swaps the table out for a spinner and unmounts the
    // panel; it remounts once data arrives, re-initialising drafts from the new
    // prop. So the panel cannot hold drafts from before the refresh — hence no
    // prop-sync effect is needed. If the loading swap is ever removed, the panel
    // would stay mounted with stale drafts and these assertions catch it.
    vi.mocked(api.users.list).mockResolvedValue([ADMIN, { ...TARGET, role: 'admin' }])
    await createUserToTriggerReload(user)

    await screen.findByText('Bob')
    expect(await screen.findByRole('combobox', { name: /role/i })).toHaveValue('admin')
    expect(screen.getByRole('button', { name: /^save$/i })).toBeDisabled()
  })
})

// ── Save role/status ──────────────────────────────────────────────────────────

describe('Users page — save role/status', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

  it('success calls update, shows toast, collapses panel, updates row', async () => {
    const user = setup()
    const updated: User = { ...TARGET, role: 'operator' }
    vi.mocked(api.users.update).mockResolvedValue(updated)
    renderPage()
    await user.click(await screen.findByText('Bob'))
    await user.selectOptions(await screen.findByRole('combobox', { name: /role/i }), 'operator')
    await user.click(screen.getByRole('button', { name: /^save$/i }))
    expect(api.users.update).toHaveBeenCalledWith(TARGET.id, { role: 'operator', is_active: true })
    expect(await screen.findByText(/user updated/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^discard$/i })).not.toBeInTheDocument()
  })

  it('error shows toast and keeps panel open', async () => {
    const user = setup()
    vi.mocked(api.users.update).mockRejectedValue(new Error('Update failed'))
    renderPage()
    await user.click(await screen.findByText('Bob'))
    await user.selectOptions(await screen.findByRole('combobox', { name: /role/i }), 'operator')
    await user.click(screen.getByRole('button', { name: /^save$/i }))
    expect(await screen.findByText(/update failed/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^discard$/i })).toBeInTheDocument()
  })
})

// ── Reset TOTP ────────────────────────────────────────────────────────────────

describe('Users page — reset TOTP', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

  it('Reset TOTP button only shown when totp_enabled', async () => {
    const user = setup() // TARGET has totp_enabled: false
    renderPage()
    await user.click(await screen.findByText('Bob'))
    await screen.findByRole('button', { name: /^discard$/i })
    expect(screen.queryByRole('button', { name: /reset totp/i })).not.toBeInTheDocument()
  })

  it('clicking Reset TOTP shows confirm/cancel', async () => {
    const user = setup({ totpEnabled: true })
    renderPage()
    await user.click(await screen.findByText('Bob'))
    await user.click(await screen.findByRole('button', { name: /reset totp/i }))
    expect(screen.getByText(/reset totp\?/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^confirm$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^cancel$/i })).toBeInTheDocument()
  })

  it('cancel hides confirm UI and does not call resetTotp', async () => {
    const user = setup({ totpEnabled: true })
    renderPage()
    await user.click(await screen.findByText('Bob'))
    await user.click(await screen.findByRole('button', { name: /reset totp/i }))
    await user.click(screen.getByRole('button', { name: /^cancel$/i }))
    expect(api.users.resetTotp).not.toHaveBeenCalled()
    expect(screen.queryByText(/reset totp\?/i)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /reset totp/i })).toBeInTheDocument()
  })

  it('confirm calls resetTotp, shows toast, collapses panel', async () => {
    const user = setup({ totpEnabled: true })
    const updated: User = { ...TARGET_TOTP, totp_enabled: false }
    vi.mocked(api.users.resetTotp).mockResolvedValue(updated)
    renderPage()
    await user.click(await screen.findByText('Bob'))
    await user.click(await screen.findByRole('button', { name: /reset totp/i }))
    await user.click(screen.getByRole('button', { name: /^confirm$/i }))
    expect(api.users.resetTotp).toHaveBeenCalledWith(TARGET_TOTP.id)
    expect(await screen.findByText(/totp reset/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^discard$/i })).not.toBeInTheDocument()
  })

  it('resetTotp error shows toast and keeps panel open', async () => {
    const user = setup({ totpEnabled: true })
    vi.mocked(api.users.resetTotp).mockRejectedValue(new Error('Reset failed'))
    renderPage()
    await user.click(await screen.findByText('Bob'))
    await user.click(await screen.findByRole('button', { name: /reset totp/i }))
    await user.click(screen.getByRole('button', { name: /^confirm$/i }))
    expect(await screen.findByText(/reset failed/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^discard$/i })).toBeInTheDocument()
  })
})
