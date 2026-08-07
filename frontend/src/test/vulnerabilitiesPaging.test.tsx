/**
 * Vulnerabilities page — pagination and filter-reset fetch contract.
 *
 * These pin the behaviour of the pagination effect, which coordinates three
 * things: `page` state, the identity of `load` (which rebuilds when filters or
 * sort change), and a `pageRef` mirror that lets `load` read the current page
 * without taking it as a dependency.
 *
 * The invariants that matter:
 *   - changing page fetches that page, exactly once
 *   - changing a filter resets to page 0 and fetches once, not twice
 */
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { vi, beforeEach, afterEach, describe, it, expect } from 'vitest'
import type { FindingRecord } from '@/lib/api'

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}))

vi.mock('@/lib/api', () => ({
  api: {
    findings: { list: vi.fn(), accept: vi.fn(), revokeAccept: vi.fn() },
    findingSettings: { get: vi.fn(), update: vi.fn() },
  },
}))

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import Vulnerabilities from '@/pages/Vulnerabilities'

const PAGE_SIZE = 50

function finding(id: number): FindingRecord {
  return {
    id,
    repo_scan_id: 1,
    advisory_id: `GHSA-${id}`,
    package: `pkg-${id}`,
    ecosystem: 'pypi',
    severity: 'high',
    first_found_at: '2024-01-01T00:00:00Z',
    closed_at: null,
    closed_reason: null,
    reopen_count: 0,
    accepted_by_id: null,
    accepted_at: null,
    accepted_reason: null,
    accepted_until: null,
    summary: null,
    details: null,
    package_version: null,
    fixed_versions: null,
    url: null,
    is_malicious: null,
    is_accepted: false,
    days_open: 3,
    sla_days: 30,
    in_breach: false,
    scan_name: `repo-${id}`,
  }
}

/** Enough total to yield 3 pages, so prev/next are both reachable. */
const TOTAL = PAGE_SIZE * 3

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
  vi.mocked(api.findings.list).mockImplementation(async (params) => ({
    items: [finding(1)],
    total: TOTAL,
    page: params?.page ?? 0,
    page_size: PAGE_SIZE,
  }))
  vi.mocked(api.findingSettings.get).mockResolvedValue({
    sla_critical_days: 7, sla_high_days: 30, sla_medium_days: 90, sla_low_days: 180,
  } as never)
  return userEvent.setup()
}

function renderPage() {
  return render(<MemoryRouter><Vulnerabilities /></MemoryRouter>)
}

/** Page numbers passed to api.findings.list, in call order.
 *
 * `params` and `params.page` are both optional on the API signature, so a
 * handler that stopped passing a page would otherwise surface as `undefined`
 * inside an array-equality mismatch. Throwing here names the actual problem.
 */
function requestedPages(): number[] {
  return vi.mocked(api.findings.list).mock.calls.map(([params], i) => {
    if (params?.page === undefined) {
      throw new Error(
        `api.findings.list call ${i} was made without a page param: ${JSON.stringify(params)}`,
      )
    }
    return params.page
  })
}

describe('Vulnerabilities — pagination fetch contract', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => { vi.restoreAllMocks() })

  it('fetches page 0 once on mount', async () => {
    setup()
    renderPage()
    await screen.findByText(/page 1 of/i)
    await waitFor(() => expect(api.findings.list).toHaveBeenCalledTimes(1))
    expect(requestedPages()).toEqual([0])
  })

  it('advancing a page fetches that page exactly once', async () => {
    const user = setup()
    renderPage()
    await screen.findByText(/page 1 of/i)
    await waitFor(() => expect(api.findings.list).toHaveBeenCalledTimes(1))

    await user.click(screen.getByRole('button', { name: '→' }))

    await screen.findByText(/page 2 of/i)
    // pageRef is written in an effect now, so this asserts the mirrored value
    // is current by the time the fetch runs — a stale ref would request 0.
    await waitFor(() => expect(requestedPages()).toEqual([0, 1]))
  })

  it('paging forward then back requests each page in order', async () => {
    const user = setup()
    renderPage()
    await screen.findByText(/page 1 of/i)
    await user.click(screen.getByRole('button', { name: '→' }))
    await screen.findByText(/page 2 of/i)
    await user.click(screen.getByRole('button', { name: '←' }))
    await screen.findByText(/page 1 of/i)
    await waitFor(() => expect(requestedPages()).toEqual([0, 1, 0]))
  })

  it('changing a filter while on a later page resets to page 0 with one fetch', async () => {
    const user = setup()
    renderPage()
    await screen.findByText(/page 1 of/i)
    await user.click(screen.getByRole('button', { name: '→' }))
    await screen.findByText(/page 2 of/i)
    await waitFor(() => expect(requestedPages()).toEqual([0, 1]))

    // Toggling a severity rebuilds `load`, which must reset to page 0 and
    // issue exactly one fetch — not one for the reset and one for the filter.
    await user.click(screen.getByRole('button', { name: /critical/i }))

    await screen.findByText(/page 1 of/i)
    await waitFor(() => expect(requestedPages()).toEqual([0, 1, 0]))
    const calls = vi.mocked(api.findings.list).mock.calls
    const lastCall = calls[calls.length - 1][0]
    expect(lastCall?.page).toBe(0)
    expect(lastCall?.severity).toEqual(['critical'])
  })

  it('a revoke that resolves after a page change refreshes the current page', async () => {
    // onDone fires only after an awaited network call, so the user can page
    // away in between. If onDone closed over the render-time `page`, it would
    // refetch the old page *after* the new one and — because it takes the
    // newest reqSeq — win the race, leaving the table showing page 1's rows
    // while the pager reads page 2.
    const user = setup()
    let releaseRevoke: () => void = () => {}
    vi.mocked(api.findings.revokeAccept).mockImplementation(
      () => new Promise<FindingRecord>(resolve => {
        releaseRevoke = () => resolve({ ...finding(1), is_accepted: false })
      }),
    )
    // Override setup()'s list mock so the row renders a Revoke button.
    vi.mocked(api.findings.list).mockImplementation(async (params) => ({
      items: [{ ...finding(1), is_accepted: true }],
      total: TOTAL,
      page: params?.page ?? 0,
      page_size: PAGE_SIZE,
    }))

    renderPage()
    await screen.findByText(/page 1 of/i)
    await waitFor(() => expect(requestedPages()).toEqual([0]))

    // Start the revoke, then page forward before it settles.
    await user.click(screen.getByRole('button', { name: /revoke/i }))
    await user.click(screen.getByRole('button', { name: '→' }))
    await screen.findByText(/page 2 of/i)
    await waitFor(() => expect(requestedPages()).toEqual([0, 1]))

    releaseRevoke()

    // The refresh triggered by onDone must target page 1 (the current page),
    // not page 0 (the page that was showing when the button was clicked).
    await waitFor(() => expect(requestedPages()).toEqual([0, 1, 1]))
    expect(screen.getByText(/page 2 of/i)).toBeInTheDocument()
  })

  it('changing a filter while already on page 0 fetches once', async () => {
    const user = setup()
    renderPage()
    await screen.findByText(/page 1 of/i)
    await waitFor(() => expect(requestedPages()).toEqual([0]))

    await user.click(screen.getByRole('button', { name: /critical/i }))

    await waitFor(() => expect(requestedPages()).toEqual([0, 0]))
  })
})
