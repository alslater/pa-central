import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { vi, beforeEach, describe, it, expect } from 'vitest'

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}))

vi.mock('@/hooks/useLiveAlerts', () => ({
  useLiveAlertsContext: () => ({
    count: 0, clear: vi.fn(), Toast: null, registerPendingOp: vi.fn(), getSessionEpoch: () => 0,
  }),
}))

vi.mock('@/lib/api', () => ({
  api: {
    repoScans: { headlines: vi.fn(), exposureHistory: vi.fn().mockResolvedValue(null), latestFixPlan: vi.fn() },
    findings:  { listAllForRepo: vi.fn(), accept: vi.fn(), revokeAccept: vi.fn() },
    risks:     { listAllForRepo: vi.fn(), accept: vi.fn(), revokeAccept: vi.fn() },
  },
}))

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import { Scans } from '@/pages/Scans'

const headline = {
  id: 1, name: 'iam', url: 'https://bitbucket.org/x/iam', latest_status: 'success' as const,
  latest_scanned_at: new Date().toISOString(),
  open_findings_by_severity: { critical: 0, high: 1, medium: 0, warning: 0, low: 0, info: 0 },
  open_risks_by_level: { critical: 0, warning: 0, info: 0 },
  breach: false, breach_count: 0, fix_count: 2,
}

const finding = {
  id: 1, repo_scan_id: 1, advisory_id: 'GHSA-a', package: 'anyio', ecosystem: 'pypi', package_version: '4.14.1',
  severity: 'high' as const, summary: 'x', first_found_at: new Date().toISOString(), closed_at: null,
  closed_reason: null, reopen_count: 0, accepted_by_id: null, accepted_at: null, accepted_reason: null,
  accepted_until: null, is_accepted: false, days_open: 1, sla_days: 30, in_breach: false, scan_name: 'iam',
}

const fixPlan = {
  status: 'planned' as const, lockfile: 'uv.lock', error: null, exit_code: 1, duration_seconds: 32.3,
  timeout_seconds: 900, near_timeout: false,
  plan: {
    lockfile: 'uv.lock', verified: true, unverified_reason: null, trial_failure: null,
    planned: [{ package: 'anyio', version: '4.14.1', target: '4.14.2', direct: false, path: [], advisories: ['GHSA-a'],
      left_open: [], fixes_all: null, fixes_all_advisories: [], cooldown_checked: true, verified: true, changes: [] }],
    held: [], commands: [['uv', 'sync']], command_changes: [], yanked_locked: [], lock_drift: [],
    lock_drift_unchecked: 0, sync: null, separate: null, separate_reason: null, deferred: [], osv_failures: 0,
    not_public: 0, yank_failures: 0,
  },
}

function renderScans() {
  return render(<MemoryRouter><Scans /></MemoryRouter>)
}

describe('Scans page fix plans', () => {
  beforeEach(() => {
    vi.mocked(useAuth).mockReturnValue({ user: { id: 1, email: 'a@example.com', display_name: 'A', role: 'admin' } } as any)
    vi.mocked(api.repoScans.headlines).mockResolvedValue([headline])
    vi.mocked(api.findings.listAllForRepo).mockResolvedValue([finding] as any)
    vi.mocked(api.risks.listAllForRepo).mockResolvedValue([])
    vi.mocked(api.repoScans.latestFixPlan).mockResolvedValue(
      { result_id: 88, completed_at: new Date().toISOString(), fix_plan: fixPlan } as any)
  })

  it('shows the fix count on the collapsed row', async () => {
    renderScans()
    expect(await screen.findByText('2 fixes')).toBeInTheDocument()
  })

  it('omits the chip when the count is null or zero', async () => {
    vi.mocked(api.repoScans.headlines).mockResolvedValue([
      headline, { ...headline, id: 2, name: 'other', fix_count: null }, { ...headline, id: 3, name: 'third', fix_count: 0 }])
    renderScans()
    await screen.findByRole('button', { name: /other/i })
    expect(screen.getAllByText(/\bfix(es)?\b/)).toHaveLength(1)
  })

  it('adds a Fix plan tab next to Findings when the project is expanded', async () => {
    const user = userEvent.setup()
    renderScans()
    await user.click(await screen.findByRole('button', { name: /iam/i }))
    const tab = await screen.findByRole('tab', { name: 'Fix plan' })
    expect(screen.getByRole('tab', { name: /Findings \(1\)/ })).toBeInTheDocument()
    expect(api.repoScans.latestFixPlan).toHaveBeenCalledWith(1)
    await user.click(tab)
    expect(screen.getByRole('tabpanel', { name: 'Fix plan' })).toHaveTextContent('4.14.2')
  })

  it('still shows findings when the plan fails to load', async () => {
    vi.mocked(api.repoScans.latestFixPlan).mockRejectedValue(new Error('boom'))
    const user = userEvent.setup()
    renderScans()
    await user.click(await screen.findByRole('button', { name: /iam/i }))
    expect(await screen.findByText('GHSA-a')).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Fix plan' })).toBeNull()
  })

  it('shows a plan on its own when there are no open findings or risks', async () => {
    vi.mocked(api.findings.listAllForRepo).mockResolvedValue([])
    const user = userEvent.setup()
    renderScans()
    await user.click(await screen.findByRole('button', { name: /iam/i }))
    expect(await screen.findByText('4.14.2', { exact: false })).toBeInTheDocument()
    expect(screen.queryByText('No open or accepted findings or risks.')).toBeNull()
  })
})
