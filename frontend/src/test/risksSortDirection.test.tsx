/**
 * Risks page — sort direction per sort key.
 *
 * There is no direction selector in the UI: each sort key implies a single
 * fixed direction chosen to lead with the most urgent record.
 *   - level: asc (critical ranks 0 in _LEVEL_RANK, so ascending is most-urgent-first)
 *   - days_open: desc (oldest-open first)
 *   - repo: asc (alphabetical, direction-neutral)
 *   - score: desc (highest score first) — the backend's sort_dir now applies
 *     directly to score with no server-side inversion, so the UI must supply
 *     the direction that keeps risky packages on top.
 */
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { vi, beforeEach, afterEach, describe, it, expect } from 'vitest'
import type { RiskRecord } from '@/lib/api'

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}))

vi.mock('@/lib/api', () => ({
  api: {
    risks: { list: vi.fn(), accept: vi.fn(), revokeAccept: vi.fn() },
  },
}))

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import Risks from '@/pages/Risks'

function risk(id: number): RiskRecord {
  return {
    id,
    repo_scan_id: 1,
    package: `pkg-${id}`,
    ecosystem: 'pypi',
    package_version: null,
    score: 42,
    level: 'warning',
    signals: [],
    first_found_at: '2024-01-01T00:00:00Z',
    closed_at: null,
    closed_reason: null,
    reopen_count: 0,
    accepted_by_id: null,
    accepted_at: null,
    accepted_reason: null,
    accepted_until: null,
    is_accepted: false,
    days_open: 3,
    scan_name: `repo-${id}`,
  }
}

function setup() {
  vi.mocked(useAuth).mockReturnValue({
    user: {
      id: 1, email: 'admin@example.com', display_name: 'Admin',
      role: 'admin', is_active: true, totp_enabled: false,
      created_at: '2024-01-01T00:00:00Z',
    },
    loading: false,
    login: vi.fn(), completeTotp: vi.fn(), logout: vi.fn(),
  })
  vi.mocked(api.risks.list).mockResolvedValue({
    items: [risk(1)], total: 1, page: 0, page_size: 50,
  })
  return userEvent.setup()
}

function renderPage() {
  return render(<MemoryRouter><Risks /></MemoryRouter>)
}

function lastCallSort() {
  const calls = vi.mocked(api.risks.list).mock.calls
  const [params] = calls[calls.length - 1]
  return { sort: params?.sort, sort_dir: params?.sort_dir }
}

describe('Risks — sort direction per key', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => { vi.restoreAllMocks() })

  it('defaults to level sort, ascending', async () => {
    setup()
    renderPage()
    await waitFor(() => expect(api.risks.list).toHaveBeenCalled())
    expect(lastCallSort()).toEqual({ sort: 'level', sort_dir: 'asc' })
  })

  it('sends desc for score, so the highest-risk packages lead', async () => {
    const user = setup()
    renderPage()
    await waitFor(() => expect(api.risks.list).toHaveBeenCalled())

    await user.selectOptions(screen.getByDisplayValue(/sort: level/i), 'score')

    await waitFor(() => expect(lastCallSort()).toEqual({ sort: 'score', sort_dir: 'desc' }))
  })

  it('sends desc for days_open, so the longest-open risks lead', async () => {
    const user = setup()
    renderPage()
    await waitFor(() => expect(api.risks.list).toHaveBeenCalled())

    await user.selectOptions(screen.getByDisplayValue(/sort: level/i), 'days_open')

    await waitFor(() => expect(lastCallSort()).toEqual({ sort: 'days_open', sort_dir: 'desc' }))
  })

  it('sends asc for repo (alphabetical)', async () => {
    const user = setup()
    renderPage()
    await waitFor(() => expect(api.risks.list).toHaveBeenCalled())

    await user.selectOptions(screen.getByDisplayValue(/sort: level/i), 'repo')

    await waitFor(() => expect(lastCallSort()).toEqual({ sort: 'repo', sort_dir: 'asc' }))
  })
})
