import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { describe, it, expect, vi } from 'vitest'
import { RecordTabs, ScanDetailTabs } from '@/components/ui'

// A selected tab can disappear when the data is refreshed (the fix plan fails to load again).
// The first tab still present must then be shown and keyboard-reachable, not a hidden panel set.

const fixPlan = {
  status: 'planned' as const, lockfile: 'uv.lock', error: null, exit_code: 1, duration_seconds: 3,
  timeout_seconds: 900, near_timeout: false,
  plan: {
    lockfile: 'uv.lock', verified: true, unverified_reason: null, trial_failure: null,
    planned: [], held: [], commands: [], command_changes: [], yanked_locked: [], lock_drift: [],
    lock_drift_unchecked: 0, sync: null, separate: null, separate_reason: null, deferred: [], osv_failures: 0,
    not_public: 0, yank_failures: 0,
  },
}

const finding = {
  id: 1, repo_scan_id: 1, advisory_id: 'GHSA-a', package: 'anyio', ecosystem: 'pypi', package_version: '4.14.1',
  severity: 'high' as const, summary: 'x', first_found_at: new Date().toISOString(), closed_at: null,
  closed_reason: null, reopen_count: 0, accepted_by_id: null, accepted_at: null, accepted_reason: null,
  accepted_until: null, is_accepted: false, days_open: 1, sla_days: 30, in_breach: false, scan_name: 'iam',
}

const risk = {
  id: 1, repo_scan_id: 1, package: 'reqeusts', ecosystem: 'pypi', package_version: null, score: 46,
  level: 'warning' as const, signals: [], first_found_at: new Date().toISOString(), closed_at: null,
  closed_reason: null, reopen_count: 0, accepted_by_id: null, accepted_at: null, accepted_reason: null,
  accepted_until: null, is_accepted: false, days_open: 3, scan_name: 'iam',
}

function expectFirstTabShownAndReachable(name: RegExp) {
  const first = screen.getByRole('tab', { name })
  expect(first).toHaveAttribute('aria-selected', 'true')
  expect(first).toHaveAttribute('tabindex', '0')
  expect(screen.getByRole('tabpanel')).toBeVisible()
  expect(screen.queryByRole('tab', { name: 'Fix plan' })).toBeNull()
}

describe('a selected tab that disappears', () => {
  it('RecordTabs falls back to the first tab present', async () => {
    const user = userEvent.setup()
    const show = vi.fn()
    const { rerender } = render(<MemoryRouter>
      <RecordTabs findings={[finding] as any} risks={[risk] as any} fixPlan={fixPlan as any} show={show} />
    </MemoryRouter>)
    await user.click(screen.getByRole('tab', { name: 'Fix plan' }))
    rerender(<MemoryRouter>
      <RecordTabs findings={[finding] as any} risks={[risk] as any} fixPlan={null} show={show} />
    </MemoryRouter>)
    expectFirstTabShownAndReachable(/Findings \(1\)/)
    screen.getByRole('tab', { name: /Findings \(1\)/ }).focus()
    await user.keyboard('{ArrowRight}')  // roving navigation works from the fallback tab
    expect(screen.getByRole('tab', { name: /Risks \(1\)/ })).toHaveAttribute('aria-selected', 'true')
  })

  it('ScanDetailTabs falls back to the first tab present', async () => {
    const user = userEvent.setup()
    const raw = [{ package: 'anyio', severity: 'high', advisory_id: 'GHSA-a', summary: 'x' }]
    const rawRisks = [{ package: 'reqeusts', level: 'warning', score: 46, signals: [] }]
    const { rerender } = render(<ScanDetailTabs findings={raw} risks={rawRisks} fixPlan={fixPlan as any} />)
    await user.click(screen.getByRole('tab', { name: 'Fix plan' }))
    rerender(<ScanDetailTabs findings={raw} risks={rawRisks} fixPlan={null} />)
    expectFirstTabShownAndReachable(/Findings \(1\)/)
  })
})
