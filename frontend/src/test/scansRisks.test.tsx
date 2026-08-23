import { render, screen, within, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { vi, beforeEach, describe, it, expect } from 'vitest'

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}))

vi.mock('@/lib/api', () => ({
  api: {
    repoScans: { headlines: vi.fn(), exposureHistory: vi.fn().mockResolvedValue({ points: [], window_days: 0 }) },
    findings:  { listAllForRepo: vi.fn(), accept: vi.fn(), revokeAccept: vi.fn() },
    risks:     { listAllForRepo: vi.fn(), accept: vi.fn(), revokeAccept: vi.fn() },
  },
}))

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import { Scans } from '@/pages/Scans'

const mockUser = { id: 1, email: 'u@example.com', display_name: 'U', role: 'viewer' as const }

const baseHeadline = {
  id: 1,
  name: 'repo-a',
  url: 'https://github.com/example/repo-a',
  latest_status: 'success' as const,
  latest_scanned_at: new Date().toISOString(),
  open_findings_by_severity: { critical: 0, high: 0, medium: 0, warning: 0, low: 0, info: 0 },
  open_risks_by_level: { critical: 0, warning: 0, info: 0 },
  breach: false,
  breach_count: 0,
}

const mockRisk = {
  id: 1, repo_scan_id: 1, package: 'reqeusts', ecosystem: 'pypi', package_version: null,
  score: 46, level: 'warning' as const,
  signals: [{ name: 'typosquat', score: 15, reason: "resembles 'requests'" }],
  first_found_at: new Date().toISOString(), closed_at: null, closed_reason: null,
  reopen_count: 0, accepted_by_id: null, accepted_at: null, accepted_reason: null,
  accepted_until: null, is_accepted: false, days_open: 3, scan_name: 'repo-a',
}

function renderScans() {
  return render(<MemoryRouter><Scans /></MemoryRouter>)
}

beforeEach(() => {
  vi.mocked(useAuth).mockReturnValue({ user: mockUser } as any)
})

describe('Scans page — project-grouped repo scans', () => {
  it('lists one row per repo scan with headline counts, and no Host Scans tab', async () => {
    vi.mocked(api.repoScans.headlines).mockResolvedValue([{
      ...baseHeadline,
      open_findings_by_severity: { critical: 1, high: 0, medium: 0, warning: 0, low: 0, info: 0 },
    }])

    renderScans()

    await screen.findByText('repo-a')
    expect(screen.queryByText('Host scans')).not.toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: /host/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument()
  })

  it('shows the risk count badge for a headline with open risks', async () => {
    vi.mocked(api.repoScans.headlines).mockResolvedValue([{
      ...baseHeadline,
      open_risks_by_level: { critical: 0, warning: 1, info: 0 },
    }])
    renderScans()

    const name = await screen.findByText('repo-a')
    const row = name.closest('[role="button"]') as HTMLElement
    expect(within(row).getByText('warning')).toBeInTheDocument()
    expect(within(row).getByText('1')).toBeInTheDocument()
  })

  it('a headline with no open findings or risks is still expandable and loads accepted-only records', async () => {
    const user = userEvent.setup()
    vi.mocked(api.repoScans.headlines).mockResolvedValue([baseHeadline])
    vi.mocked(api.findings.listAllForRepo).mockResolvedValue([])
    vi.mocked(api.risks.listAllForRepo).mockResolvedValue([{ ...mockRisk, is_accepted: true }])

    renderScans()
    const row = await screen.findByRole('button', { name: /repo-a/i })
    await user.click(row)

    expect(await screen.findByText('reqeusts')).toBeInTheDocument()
    expect(api.findings.listAllForRepo).toHaveBeenCalledWith(1)
    expect(api.risks.listAllForRepo).toHaveBeenCalledWith(1)
  })

  it('expands a project row to show Findings/Risks tabs backed by listAllForRepo', async () => {
    const user = userEvent.setup()
    vi.mocked(api.repoScans.headlines).mockResolvedValue([{
      ...baseHeadline,
      open_risks_by_level: { critical: 0, warning: 1, info: 0 },
    }])
    vi.mocked(api.findings.listAllForRepo).mockResolvedValue([])
    vi.mocked(api.risks.listAllForRepo).mockResolvedValue([mockRisk])

    renderScans()
    const row = await screen.findByRole('button', { name: /repo-a/i })
    await user.click(row)

    expect(await screen.findByText('reqeusts')).toBeInTheDocument()
    expect(api.findings.listAllForRepo).toHaveBeenCalledWith(1)
    expect(api.risks.listAllForRepo).toHaveBeenCalledWith(1)
  })

  it('shows an SLA breach badge with the breach count', async () => {
    vi.mocked(api.repoScans.headlines).mockResolvedValue([{
      ...baseHeadline,
      breach: true,
      breach_count: 3,
    }])
    renderScans()

    await screen.findByText('repo-a')
    expect(screen.getByText(/SLA breach ×3/)).toBeInTheDocument()
  })

  it('shows an empty state when there are no repo scans', async () => {
    vi.mocked(api.repoScans.headlines).mockResolvedValue([])
    renderScans()

    expect(await screen.findByText(/no repo scans/i)).toBeInTheDocument()
  })

  it('shows a distinct error state (not the empty state) when headlines() rejects', async () => {
    vi.mocked(api.repoScans.headlines).mockRejectedValue(new Error('network down'))
    renderScans()

    expect(await screen.findByText(/failed to load scans/i)).toBeInTheDocument()
    expect(screen.queryByText(/no repo scans/i)).not.toBeInTheDocument()
  })

  it('Retry after a failed headlines() fetch re-fetches and renders rows on success', async () => {
    const user = userEvent.setup()
    vi.mocked(api.repoScans.headlines)
      .mockRejectedValueOnce(new Error('network down'))
      .mockResolvedValueOnce([baseHeadline])

    renderScans()
    await screen.findByText(/failed to load scans/i)

    await user.click(screen.getByRole('button', { name: /retry/i }))

    await screen.findByText('repo-a')
    expect(screen.queryByText(/failed to load scans/i)).not.toBeInTheDocument()
  })

  it('accepting a risk through RecordTabs refreshes in the background without a full-page loading flash or collapsing the row', async () => {
    const user = userEvent.setup()
    vi.mocked(api.repoScans.headlines).mockClear()
    vi.mocked(api.risks.listAllForRepo).mockClear()
    vi.mocked(api.findings.listAllForRepo).mockClear()
    vi.mocked(api.risks.accept).mockClear()

    // The second headlines() call (the one triggered by the accept) is held
    // open with a manually-resolved promise instead of mockResolvedValueOnce.
    // This matters: with a normal fast-resolving mock, a real `loading=true`
    // regression resolves within a microtask and settles before any assertion
    // can query for it, so the test would pass whether or not the bug is
    // present — the exact trap this fix's brief warns about (React 19's
    // remount/batching behaviour cannot be verified by reasoning, only by
    // observation). Deferring the second call lets the test inspect the DOM
    // while that request is genuinely in flight.
    let resolveSecondHeadlines: (v: typeof baseHeadline[]) => void = () => {}
    let headlinesCallCount = 0
    vi.mocked(api.repoScans.headlines).mockImplementation(() => {
      headlinesCallCount += 1
      if (headlinesCallCount === 1) {
        return Promise.resolve([{
          ...baseHeadline,
          open_risks_by_level: { critical: 0, warning: 1, info: 0 },
        }])
      }
      return new Promise(res => { resolveSecondHeadlines = res })
    })
    vi.mocked(api.risks.listAllForRepo)
      .mockResolvedValueOnce([mockRisk])
      .mockResolvedValueOnce([{ ...mockRisk, is_accepted: true, accepted_reason: 'fine for now' }])
    vi.mocked(api.findings.listAllForRepo).mockResolvedValue([])
    vi.mocked(api.risks.accept).mockResolvedValue({ ...mockRisk, is_accepted: true })

    renderScans()

    const row = await screen.findByRole('button', { name: /repo-a/i })
    await user.click(row)
    expect(row).toHaveAttribute('aria-expanded', 'true')

    // Open the risk's detail drawer and accept it.
    const riskRow = await screen.findByRole('button', { name: /reqeusts — view details/i })
    await user.click(riskRow)
    await user.click(await screen.findByRole('button', { name: /accept risk/i }))
    await user.type(screen.getByLabelText(/reason/i), 'fine for now')
    await user.click(screen.getByRole('button', { name: /^save$/i }))
    await screen.findByText('Risk accepted')

    // The second headlines() call (from the background refresh) is now
    // genuinely in flight, deliberately held open above. Assert on the DOM
    // while it is pending — this is the moment a full-page flash would show.
    await waitFor(() => expect(headlinesCallCount).toBe(2))
    expect(screen.queryByText('Loading…')).not.toBeInTheDocument()
    expect(document.body.contains(row)).toBe(true)
    expect(row).toHaveAttribute('aria-expanded', 'true')

    // Let the deferred refresh resolve and confirm the page settles normally,
    // with the same row (not a remounted one) still expanded, and the
    // headline's warning-risk badge cleared now that the risk is accepted.
    resolveSecondHeadlines([{
      ...baseHeadline,
      open_risks_by_level: { critical: 0, warning: 0, info: 0 },
    }])
    await waitFor(() => expect(within(row).queryByText('warning')).not.toBeInTheDocument())
    expect(document.body.contains(row)).toBe(true)
    expect(row).toHaveAttribute('aria-expanded', 'true')
  })
})

describe('Scans page — overlapping detail loads', () => {
  it('a slower background refresh cannot overwrite a faster, more recent one', async () => {
    const user = userEvent.setup()
    vi.mocked(api.repoScans.headlines).mockResolvedValue([baseHeadline])
    vi.mocked(api.risks.accept).mockResolvedValue({ ...mockRisk, is_accepted: true })
    vi.mocked(api.risks.revokeAccept).mockResolvedValue({ ...mockRisk, is_accepted: false })
    // A finding is present in every findings.listAllForRepo() response so
    // RecordTabs always renders the "Findings (N)" tab (only hidden when
    // *both* findings and risks are empty) — its count is this test's
    // observable signal for which background refresh last committed state.
    const mockFinding = { id: 1, repo_scan_id: 1, advisory_id: 'GHSA-x', package: 'flask' } as any
    const riskA = { ...mockRisk, id: 1, package: 'risk-a' }
    const riskB = { ...mockRisk, id: 2, package: 'risk-b' }

    // Initial expand load (call #1) resolves immediately and normally, so
    // the panel becomes interactive. Accepting riskA then triggers
    // RecordTabs' onChanged -> loadDetail(true) as call #2, which this test
    // holds open — deliberately using a *different* risk than riskB (rather
    // than accept-then-revoke on the same risk) because the accepted/
    // unaccepted UI a user can act on is driven by the risks state from the
    // *last committed* load, not by the in-flight one: revoking the same
    // risk again would need call #2's stuck response to have landed first.
    // Accepting riskB immediately after triggers call #3, which resolves
    // right away — simulating a second background refresh finishing before
    // an earlier one that's still in flight. Without request sequencing,
    // call #2's .then() would run last and overwrite call #3's fresher
    // findings/risks with its own stale data.
    let resolveSecondFindings: (v: (typeof mockFinding)[]) => void = () => {}
    let findingsCallCount = 0
    vi.mocked(api.findings.listAllForRepo).mockImplementation(() => {
      findingsCallCount += 1
      if (findingsCallCount === 2) {
        return new Promise(res => { resolveSecondFindings = res })
      }
      // Calls #1 and #3 resolve immediately. #3's list (two entries) is
      // distinct from #2's eventual one-entry list so the assertion can
      // tell which one actually landed.
      return Promise.resolve([mockFinding, { ...mockFinding, id: 2, advisory_id: 'GHSA-y' }])
    })
    vi.mocked(api.risks.listAllForRepo)
      .mockResolvedValueOnce([riskA, riskB])
      .mockResolvedValueOnce([{ ...riskA, is_accepted: true, accepted_reason: 'fine for now' }, riskB])
      .mockResolvedValueOnce([
        { ...riskA, is_accepted: true, accepted_reason: 'fine for now' },
        { ...riskB, is_accepted: true, accepted_reason: 'also fine' },
      ])

    renderScans()
    const row = await screen.findByRole('button', { name: /repo-a/i })
    await user.click(row)
    await screen.findByText('Findings (2)') // call #1 landed

    // Accept riskA: triggers call #2 (background), which this test holds
    // open via resolveSecondFindings.
    await user.click(await screen.findByRole('tab', { name: /risks/i }))
    await user.click(await screen.findByRole('button', { name: /risk-a — view details/i }))
    await user.click(await screen.findByRole('button', { name: /accept risk/i }))
    await user.type(screen.getByLabelText(/reason/i), 'fine for now')
    await user.click(screen.getByRole('button', { name: /^save$/i }))
    await screen.findByText('Risk accepted')
    await waitFor(() => expect(findingsCallCount).toBe(2))

    // Accept riskB: triggers call #3 (background), which resolves right
    // away — landing before call #2, which is still stuck. riskB's own
    // unaccepted state came from call #1 (already committed), so this
    // interaction doesn't depend on call #2 having resolved.
    await user.click(await screen.findByRole('tab', { name: /risks/i }))
    await user.click(await screen.findByRole('button', { name: /risk-b — view details/i }))
    await user.click(await screen.findByRole('button', { name: /accept risk/i }))
    await user.type(screen.getByLabelText(/reason/i), 'also fine')
    await user.click(screen.getByRole('button', { name: /^save$/i }))
    await screen.findByText('Risk accepted')
    await waitFor(() => expect(findingsCallCount).toBe(3))
    await screen.findByText('Findings (2)') // call #3 landed

    // Now let the older, slower call #2 resolve with its stale, one-entry
    // findings list. It must not overwrite call #3's already-committed
    // two-entry state.
    resolveSecondFindings([mockFinding])
    await new Promise(r => setTimeout(r, 0)) // flush any pending state update
    expect(screen.getByText('Findings (2)')).toBeInTheDocument()
    expect(screen.queryByText('Findings (1)')).not.toBeInTheDocument()
  })
})

describe('Scans page — overlapping headline refreshes', () => {
  it('a slower background headlines refresh cannot overwrite a faster, more recent one', async () => {
    const user = userEvent.setup()
    vi.mocked(api.findings.accept).mockResolvedValue({} as any)
    vi.mocked(api.risks.accept).mockResolvedValue({ ...mockRisk, is_accepted: true })
    const mockFinding = {
      id: 1, repo_scan_id: 1, advisory_id: 'GHSA-x', package: 'flask',
      severity: 'high', is_accepted: false, days_open: 3, scan_name: 'repo-a',
      first_found_at: new Date().toISOString(), closed_at: null, closed_reason: null,
      reopen_count: 0, accepted_by_id: null, accepted_at: null, accepted_reason: null,
      accepted_until: null, sla_days: 14, in_breach: false,
    } as any

    // Initial mount load (call #1) resolves immediately. Accepting the
    // finding then triggers Scans' onChanged -> loadHeadlinesBackground
    // -> load(true) as call #2, which this test holds open. Accepting the
    // risk right after triggers call #3, which resolves immediately —
    // simulating a second background headlines refresh finishing before an
    // earlier one still in flight. Without request sequencing, call #2's
    // .then() would run last and overwrite call #3's fresher counts.
    let resolveSecondHeadlines: (v: (typeof baseHeadline)[]) => void = () => {}
    let headlinesCallCount = 0
    vi.mocked(api.repoScans.headlines).mockImplementation(() => {
      headlinesCallCount += 1
      if (headlinesCallCount === 1) {
        return Promise.resolve([baseHeadline])
      }
      if (headlinesCallCount === 2) {
        return new Promise(res => { resolveSecondHeadlines = res })
      }
      // Call #3's critical count (2) is distinct from call #2's eventual
      // one (1) so the assertion can tell which one actually landed.
      return Promise.resolve([{
        ...baseHeadline,
        open_findings_by_severity: { ...baseHeadline.open_findings_by_severity, critical: 2 },
      }])
    })
    vi.mocked(api.findings.listAllForRepo).mockResolvedValue([mockFinding])
    vi.mocked(api.risks.listAllForRepo).mockResolvedValue([mockRisk])

    renderScans()
    const row = await screen.findByRole('button', { name: /repo-a/i })
    await user.click(row) // expand triggers ProjectRow's own detail load, unrelated to this race

    // Accept the finding: triggers call #2 (background headlines refresh),
    // which this test holds open via resolveSecondHeadlines.
    await user.click(await screen.findByRole('button', { name: /flask GHSA-x — view details/i }))
    await user.click(await screen.findByRole('button', { name: /accept finding/i }))
    await user.type(screen.getByLabelText(/reason/i), 'known issue')
    await user.click(screen.getByRole('button', { name: /^save$/i }))
    await screen.findByText('Finding accepted')
    await waitFor(() => expect(headlinesCallCount).toBe(2))

    // Accept the risk: triggers call #3 (background headlines refresh),
    // which resolves right away — landing before call #2, which is still
    // stuck. The risk's own unaccepted state came from the initial detail
    // load (already committed), so this doesn't depend on call #2.
    await user.click(await screen.findByRole('tab', { name: /risks/i }))
    await user.click(await screen.findByRole('button', { name: /reqeusts — view details/i }))
    await user.click(await screen.findByRole('button', { name: /accept risk/i }))
    await user.type(screen.getByLabelText(/reason/i), 'fine for now')
    await user.click(screen.getByRole('button', { name: /^save$/i }))
    await screen.findByText('Risk accepted')
    await waitFor(() => expect(headlinesCallCount).toBe(3))
    await screen.findByText('2') // call #3's critical count landed

    // Now let the older, slower call #2 resolve with its stale count. It
    // must not overwrite call #3's already-committed critical count.
    resolveSecondHeadlines([{
      ...baseHeadline,
      open_findings_by_severity: { ...baseHeadline.open_findings_by_severity, critical: 1 },
    }])
    await new Promise(r => setTimeout(r, 0)) // flush any pending state update
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.queryByText('1')).not.toBeInTheDocument()
  })
})

describe('Scans page — project filter', () => {
  it('narrows the list to projects whose name matches the filter text', async () => {
    const user = userEvent.setup()
    vi.mocked(api.repoScans.headlines).mockResolvedValue([
      { ...baseHeadline, id: 1, name: 'payments-service' },
      { ...baseHeadline, id: 2, name: 'auth-service' },
      { ...baseHeadline, id: 3, name: 'billing-worker' },
    ])

    renderScans()
    await screen.findByText('payments-service')
    expect(screen.getByText('auth-service')).toBeInTheDocument()
    expect(screen.getByText('billing-worker')).toBeInTheDocument()

    await user.type(screen.getByLabelText(/filter projects/i), 'service')

    expect(screen.getByText('payments-service')).toBeInTheDocument()
    expect(screen.getByText('auth-service')).toBeInTheDocument()
    expect(screen.queryByText('billing-worker')).not.toBeInTheDocument()
  })

  it('is case-insensitive and shows an empty state when nothing matches', async () => {
    const user = userEvent.setup()
    vi.mocked(api.repoScans.headlines).mockResolvedValue([
      { ...baseHeadline, id: 1, name: 'payments-service' },
    ])

    renderScans()
    await screen.findByText('payments-service')

    await user.type(screen.getByLabelText(/filter projects/i), 'PAYMENTS')
    expect(screen.getByText('payments-service')).toBeInTheDocument()

    await user.clear(screen.getByLabelText(/filter projects/i))
    await user.type(screen.getByLabelText(/filter projects/i), 'nonexistent')
    expect(screen.queryByText('payments-service')).not.toBeInTheDocument()
    expect(screen.getByText(/no projects match this filter/i)).toBeInTheDocument()
  })
})
