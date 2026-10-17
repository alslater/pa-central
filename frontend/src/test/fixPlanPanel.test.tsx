import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi } from 'vitest'
import { FixPlanPanel, formatDuration } from '@/components/FixPlanPanel'
import type { FixPlanResult } from '@/lib/api'

const base: FixPlanResult = {
  status: 'planned', lockfile: 'backend/uv.lock', error: null, exit_code: 1,
  duration_seconds: 344.2, timeout_seconds: 900, near_timeout: false,
  plan: {
    lockfile: 'backend/uv.lock',
    planned: [{ package: 'requests', version: '2.31.0', target: '2.33.0', direct: true, path: ['p', 'requests'],
      advisories: ['GHSA-1', 'GHSA-2'], left_open: [], fixes_all: null, fixes_all_advisories: [],
      cooldown_checked: true, verified: true, changes: [], parent: null, more_parents: [], forced: null,
      by_relock: false }],
    held: [{ package: 'django', version: '4.2.0', target: '5.2.1', reason: 'major upgrade',
      advisories: ['GHSA-3'], detail: '', cadence: null, needs_major: ['django'] }],
    commands: [['uv', 'lock', '--upgrade-package', 'requests==2.33.0'], ['uv', 'sync']],
    command_changes: [], yanked_locked: [], trial_failure: null, lock_drift: [], lock_drift_unchecked: 0,
    sync: null, separate: null, separate_reason: null, deferred: [],
    osv_failures: 0, not_public: 0, yank_failures: 0, verified: true, unverified_reason: null,
  },
}

describe('FixPlanPanel', () => {
  it('shows the lock file, verified tag, commands and tables', () => {
    render(<FixPlanPanel fixPlan={base} />)
    expect(screen.getByText('backend/uv.lock')).toBeInTheDocument()
    expect(screen.getByText('Verified')).toBeInTheDocument()
    expect(screen.getByText(/uv lock --upgrade-package requests==2\.33\.0/)).toBeInTheDocument()
    expect(screen.getByText('2.31.0 → 2.33.0')).toBeInTheDocument()
    expect(screen.getByText('major upgrade')).toBeInTheDocument()
    expect(screen.getByText(/--allow-major django/)).toBeInTheDocument()
  })

  it('says when the commands apply only the first fix, and what to re-run for', () => {
    // As package-alert prints separate mode: copied commands are not the whole remediation.
    render(<FixPlanPanel fixPlan={{ ...base, plan: { ...base.plan!, separate: true,
      separate_reason: 'their upgrades conflict', deferred: ['urllib3', 'zipp'] } }} />)
    expect(screen.getByText(/These fixes could not be verified as one command: their upgrades conflict\. Only the first is printed\./))
      .toBeInTheDocument()
    expect(screen.getByText('Next, after applying that and re-running pa fix: urllib3, zipp')).toBeInTheDocument()
  })

  it('discloses versions whose withdrawn-release check failed', () => {
    render(<FixPlanPanel fixPlan={{ ...base, plan: { ...base.plan!, lock_drift_unchecked: 2 } }} />)
    expect(screen.getByText(/2 version\(s\) that re-locking the project installs could not be checked for withdrawn releases\./))
      .toBeInTheDocument()
  })

  it('says nothing about withdrawn-release checks when they all ran', () => {
    render(<FixPlanPanel fixPlan={base} />)
    expect(screen.queryByText(/withdrawn releases/)).toBeNull()
  })

  it('says nothing about separate mode for a combined plan', () => {
    render(<FixPlanPanel fixPlan={base} />)
    expect(screen.queryByText(/could not be verified as one command/)).toBeNull()
    expect(screen.queryByText(/re-running pa fix/)).toBeNull()
  })

  it('shows the unverified reason', () => {
    render(<FixPlanPanel fixPlan={{ ...base, plan: { ...base.plan!, verified: false,
      unverified_reason: 'bwrap (bubblewrap) is not installed' } }} />)
    expect(screen.getByText('Unverified')).toBeInTheDocument()
    expect(screen.getByText(/bwrap \(bubblewrap\) is not installed/)).toBeInTheDocument()
  })

  it('renders trial_failure and hold details verbatim', () => {
    render(<FixPlanPanel fixPlan={{ ...base, plan: { ...base.plan!, planned: [], commands: [],
      trial_failure: '401 Unauthorized from https://pypi.internal.example',
      held: [{ ...base.plan!.held[0], reason: 'could not verify', detail: 'trial resolve failed: 401' }] } }} />)
    expect(screen.getByText(/Every trial failed the same way/)).toBeInTheDocument()
    expect(screen.getByText(/401 Unauthorized from https:\/\/pypi\.internal\.example/)).toBeInTheDocument()
    expect(screen.getByText('trial resolve failed: 401')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /copy/i })).toBeNull()
  })

  it('copies the commands', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })
    render(<FixPlanPanel fixPlan={base} />)
    await userEvent.click(screen.getByRole('button', { name: /copy commands/i }))
    expect(writeText).toHaveBeenCalledWith('uv lock --upgrade-package requests==2.33.0\nuv sync')
  })

  it.each([
    ['unsupported', 'No supported lock file'],
    ['error', 'registry login failed for https://a/simple'],
    ['skipped', 'the installed package-alert has no pa fix'],
    ['timeout', 'pa fix did not finish within 900 s'],
  ] as const)('shows the %s message', (status, error) => {
    render(<FixPlanPanel fixPlan={{ ...base, status, error, plan: null }} />)
    expect(screen.getByText(error)).toBeInTheDocument()
  })

  it('skips malformed command entries and still renders', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })
    render(<FixPlanPanel fixPlan={{ ...base, plan: { ...base.plan!,
      commands: ['not-an-array', ['uv', 7], [], ['uv', 'sync']] } }} />)
    expect(screen.getByText('backend/uv.lock')).toBeInTheDocument()
    expect(screen.getByText('uv sync')).toBeInTheDocument()
    expect(screen.queryByText(/not-an-array/)).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: /copy commands/i }))
    expect(writeText).toHaveBeenCalledWith('uv sync')
  })

  it('shows an error toast, without crashing, when the clipboard is unavailable', async () => {
    Object.assign(navigator, { clipboard: undefined })
    render(<FixPlanPanel fixPlan={base} />)
    await userEvent.click(screen.getByRole('button', { name: /copy commands/i }))
    expect(await screen.findByText('Could not copy')).toBeInTheDocument()
  })

  it('formats durations', () => {
    expect(formatDuration(344.2)).toBe('5m 44s')
    expect(formatDuration(900)).toBe('15m')
    expect(formatDuration(42)).toBe('42s')
  })
})
