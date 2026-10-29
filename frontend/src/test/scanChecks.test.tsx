import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router'
import { vi, beforeEach, describe, it, expect } from 'vitest'

// not_public and yank results (package-alert #121) on host scans and repo-scan results.
// A yank count is shown only when yank_checked is true: the backend stores null otherwise, and
// "0 yanked" would claim a check that never ran.

vi.mock('@/hooks/useAuth', () => ({ useAuth: vi.fn() }))

vi.mock('@/hooks/useLiveAlerts', () => ({
  useLiveAlertsContext: () => ({
    count: 0, clear: vi.fn(), Toast: null, registerPendingOp: vi.fn(), getSessionEpoch: () => 0,
  }),
}))

vi.mock('@/lib/api', () => ({
  api: {
    hosts:   { get: vi.fn(), latestScans: vi.fn() },
    alerts:  { list: vi.fn() },
    configs: { list: vi.fn(), forHost: vi.fn() },
    repoScans: {
      list: vi.fn(), results: vi.fn(),
      scanOptions: vi.fn().mockResolvedValue({ flags: [], exclusions: [] }),
      create: vi.fn(), update: vi.fn(), delete: vi.fn(), trigger: vi.fn(),
    },
    repoCredentials: { list: vi.fn() },
    systemSettings:  { list: vi.fn() },
  },
}))

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import HostDetail from '@/pages/HostDetail'
import RepoScans from '@/pages/RepoScans'

const YANKED = { ecosystem: 'PyPI', package: 'requests', version: '2.32.0', reason: 'broken wheel' }

const NOT_CHECKED = { not_public: 0, yank_checked: false, yanked: null, yank_failures: null }

function hostScan(checks: Record<string, unknown>) {
  return {
    id: 1, host_id: 1, project_path: '/app/checks', scan_type: 'project',
    status: 'clean', finding_count: 0, findings: null, risks: [],
    risk_failures: 0, osv_failures: 0, sources: null, remediations: null,
    scanned_at: '2026-10-29T00:00:00Z', received_at: '2026-10-29T00:00:00Z',
    ...NOT_CHECKED, ...checks,
  }
}

function repoResult(checks: Record<string, unknown>) {
  return {
    id: 10, repo_scan_id: 1, status: 'success', triggered_by: 'manual',
    pa_version: '0.11.0', finding_count: 0, findings: [], risks: [],
    risk_failures: 0, osv_failures: 0, sources: null, remediations: null, fix_plan: null,
    error_message: null, ecs_task_arn: null, notified: false,
    started_at: '2026-10-29T00:00:00Z', completed_at: '2026-10-29T00:01:00Z',
    ...NOT_CHECKED, ...checks,
  }
}

const mockRepoScan = {
  id: 1, name: 'my-repo', url: 'https://github.com/example/my-repo', branch: 'main',
  cron_schedule: null, cron_timezone: null, is_enabled: true, credential_id: null,
  config_template_id: null, pa_version: null, scan_flags: null, subfolder: null,
  sla_high_days: null, sla_medium_days: null, min_notify_severity: 'medium' as const,
  notify_recipients: [], last_scan_at: null, created_at: '2026-08-20T00:00:00Z',
  updated_at: '2026-08-20T00:00:00Z', created_by_id: 1, breach: false, breach_count: 0,
  scan_config_hash: null,
}

beforeEach(() => {
  vi.mocked(useAuth).mockReturnValue({ user: { id: 1, role: 'admin' } } as any)
  vi.mocked(api.hosts.get).mockResolvedValue({
    id: 1, name: 'web-01', hostname: 'web-01.local', daemon_status: 'running', tags: [],
    last_seen_at: null, pa_version: null, description: null, daemon_uptime_seconds: null,
  } as any)
  vi.mocked(api.alerts.list).mockResolvedValue([])
  vi.mocked(api.configs.list).mockResolvedValue([])
  vi.mocked(api.configs.forHost).mockResolvedValue(null)
  vi.mocked(api.repoScans.list).mockResolvedValue([mockRepoScan] as any)
  vi.mocked(api.repoCredentials.list).mockResolvedValue([])
  vi.mocked(api.systemSettings.list).mockResolvedValue([])
})

async function openHostScan(checks: Record<string, unknown>) {
  vi.mocked(api.hosts.latestScans).mockResolvedValue([hostScan(checks)] as any)
  const user = userEvent.setup()
  render(
    <MemoryRouter initialEntries={['/hosts/1']}>
      <Routes><Route path="/hosts/:id" element={<HostDetail />} /></Routes>
    </MemoryRouter>,
  )
  await user.click(await screen.findByRole('tab', { name: /scans/i }))
  await screen.findByText('/app/checks')
  return user
}

async function openRepoResult(checks: Record<string, unknown>) {
  vi.mocked(api.repoScans.results).mockResolvedValue([repoResult(checks)] as any)
  const user = userEvent.setup()
  render(<MemoryRouter><RepoScans /></MemoryRouter>)
  await user.click(await screen.findByRole('button', { name: /expand results/i }))
  await screen.findByText('0 findings')
  return user
}

describe.each([
  ['host scan', openHostScan],
  ['repo-scan result', openRepoResult],
] as const)('%s — scan checks', (_label, open) => {
  it('shows a not-public chip that does not read as a failure', async () => {
    await open({ not_public: 3 })
    const chip = screen.getByText('3 not public')
    expect(chip).toHaveAttribute('title', expect.stringMatching(/not looked up/i))
    expect(chip.textContent).not.toMatch(/⚠/)
  })

  it('shows no not-public chip when the count is 0', async () => {
    await open({ not_public: 0 })
    expect(screen.queryByText(/not public/)).not.toBeInTheDocument()
  })

  it('shows no yank count at all when the yank check did not run', async () => {
    await open({ yank_checked: false, yanked: null, yank_failures: null })
    expect(screen.queryByText(/yank/i)).not.toBeInTheDocument()
  })

  it('shows no "0 yanked" chip when the check ran and found nothing', async () => {
    await open({ yank_checked: true, yanked: [], yank_failures: 0 })
    expect(screen.queryByText(/yank/i)).not.toBeInTheDocument()
  })

  it('shows a yanked chip and lists the yanked versions when expanded', async () => {
    const user = await open({ yank_checked: true, yanked: [YANKED], yank_failures: 0 })
    const chip = screen.getByText('⚠ 1 yanked')
    const row = chip.closest('[role="button"]') as HTMLElement
    expect(row).not.toBeNull()
    await user.click(row)
    expect(screen.getByText('requests')).toBeInTheDocument()
    expect(screen.getByText('2.32.0')).toBeInTheDocument()
    expect(screen.getByText('broken wheel')).toBeInTheDocument()
  })

  it('warns when some yank lookups failed', async () => {
    await open({ yank_checked: true, yanked: [], yank_failures: 2 })
    expect(screen.getByText('⚠ 2 yank-unchecked')).toBeInTheDocument()
  })
})
