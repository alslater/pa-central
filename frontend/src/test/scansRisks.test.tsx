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
