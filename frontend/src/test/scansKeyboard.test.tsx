import { render, screen } from '@testing-library/react'
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

function renderScans() {
  return render(<MemoryRouter><Scans /></MemoryRouter>)
}

beforeEach(() => {
  vi.mocked(useAuth).mockReturnValue({ user: mockUser } as any)
})

describe('Scans row keyboard accessibility', () => {
  it('row with open findings is focusable and announces expansion state', async () => {
    vi.mocked(api.repoScans.headlines).mockResolvedValue([{
      ...baseHeadline,
      open_findings_by_severity: { critical: 0, high: 1, medium: 0, warning: 0, low: 0, info: 0 },
    }])

    renderScans()
    const row = await screen.findByRole('button', { name: /repo-a/i })
    expect(row).toHaveAttribute('tabindex', '0')
    expect(row).toHaveAttribute('aria-expanded', 'false')
  })

  it('Enter key expands a row that has open findings', async () => {
    const user = userEvent.setup()
    vi.mocked(api.repoScans.headlines).mockResolvedValue([{
      ...baseHeadline,
      open_findings_by_severity: { critical: 0, high: 1, medium: 0, warning: 0, low: 0, info: 0 },
    }])
    vi.mocked(api.findings.listAllForRepo).mockResolvedValue([{
      id: 1, repo_scan_id: 1, advisory_id: 'GHSA-xxxx', package: 'vuln-pkg', ecosystem: 'npm',
      severity: 'high', first_found_at: new Date().toISOString(), closed_at: null, closed_reason: null,
      reopen_count: 0, accepted_by_id: null, accepted_at: null, accepted_reason: null, accepted_until: null,
      summary: 'Bad', details: null, package_version: null, fixed_versions: null, url: null,
      is_malicious: false, days_open: 1, sla_days: null, in_breach: false, scan_name: 'repo-a',
    } as any])
    vi.mocked(api.risks.listAllForRepo).mockResolvedValue([])

    renderScans()
    const row = await screen.findByRole('button', { name: /repo-a/i })
    row.focus()
    await user.keyboard('{Enter}')
    expect(row).toHaveAttribute('aria-expanded', 'true')
    expect(await screen.findByText('vuln-pkg')).toBeInTheDocument()
  })

  it('Space key expands a row that has open findings', async () => {
    const user = userEvent.setup()
    vi.mocked(api.repoScans.headlines).mockResolvedValue([{
      ...baseHeadline,
      open_findings_by_severity: { critical: 0, high: 0, medium: 1, warning: 0, low: 0, info: 0 },
    }])
    vi.mocked(api.findings.listAllForRepo).mockResolvedValue([])
    vi.mocked(api.risks.listAllForRepo).mockResolvedValue([])

    renderScans()
    const row = await screen.findByRole('button', { name: /repo-a/i })
    row.focus()
    await user.keyboard(' ')
    expect(row).toHaveAttribute('aria-expanded', 'true')
  })

  it('Enter key collapses an already-expanded row', async () => {
    const user = userEvent.setup()
    vi.mocked(api.repoScans.headlines).mockResolvedValue([{
      ...baseHeadline,
      open_findings_by_severity: { critical: 0, high: 0, medium: 0, warning: 0, low: 1, info: 0 },
    }])
    vi.mocked(api.findings.listAllForRepo).mockResolvedValue([])
    vi.mocked(api.risks.listAllForRepo).mockResolvedValue([])

    renderScans()
    const row = await screen.findByRole('button', { name: /repo-a/i })
    row.focus()
    await user.keyboard('{Enter}')
    expect(row).toHaveAttribute('aria-expanded', 'true')
    await user.keyboard('{Enter}')
    expect(row).toHaveAttribute('aria-expanded', 'false')
  })

  it('row without open findings or risks is still focusable and has a button role', async () => {
    vi.mocked(api.repoScans.headlines).mockResolvedValue([baseHeadline])
    vi.mocked(api.findings.listAllForRepo).mockResolvedValue([])
    vi.mocked(api.risks.listAllForRepo).mockResolvedValue([])

    renderScans()
    const row = await screen.findByRole('button', { name: /repo-a/i })
    expect(row).toHaveAttribute('tabindex', '0')
  })

  it('Enter key expands a row without open findings or risks and shows the all-accepted empty message', async () => {
    const user = userEvent.setup()
    vi.mocked(api.repoScans.headlines).mockResolvedValue([baseHeadline])
    vi.mocked(api.findings.listAllForRepo).mockResolvedValue([])
    vi.mocked(api.risks.listAllForRepo).mockResolvedValue([])

    renderScans()
    const row = await screen.findByRole('button', { name: /repo-a/i })
    row.focus()
    await user.keyboard('{Enter}')
    expect(row).toHaveAttribute('aria-expanded', 'true')
    expect(await screen.findByText(/no open or accepted findings or risks/i)).toBeInTheDocument()
  })
})
