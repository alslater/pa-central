import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { vi, beforeEach, describe, it, expect } from 'vitest'

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}))

vi.mock('@/lib/api', () => ({
  api: {
    repoScans:       {
      list:        vi.fn(),
      results:     vi.fn(),
      scanOptions: vi.fn().mockResolvedValue({ flags: [], exclusions: [] }),
      create:      vi.fn(),
      update:      vi.fn(),
      delete:      vi.fn(),
      trigger:     vi.fn(),
    },
    repoCredentials: { list: vi.fn() },
    configs:         { list: vi.fn() },
    systemSettings:  { list: vi.fn() },
  },
}))

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import RepoScans from '@/pages/RepoScans'

const mockUser = { id: 1, email: 'u@example.com', display_name: 'U', role: 'admin' as const }

const mockScan = {
  id: 1, name: 'my-repo', url: 'https://github.com/example/my-repo', branch: 'main',
  cron_schedule: null, cron_timezone: null, is_enabled: true, credential_id: null,
  config_template_id: null, pa_version: null, scan_flags: null, subfolder: null,
  sla_high_days: null, sla_medium_days: null, min_notify_severity: 'medium' as const,
  notify_recipients: [], last_scan_at: null, created_at: '2026-08-20T00:00:00Z',
  updated_at: '2026-08-20T00:00:00Z', created_by_id: 1, breach: false, breach_count: 0,
  scan_config_hash: null,
}

function renderRepoScans() {
  return render(<MemoryRouter><RepoScans /></MemoryRouter>)
}

beforeEach(() => {
  vi.mocked(useAuth).mockReturnValue({ user: mockUser } as any)
  vi.mocked(api.repoScans.list).mockResolvedValue([mockScan] as any)
  vi.mocked(api.repoCredentials.list).mockResolvedValue([])
  vi.mocked(api.configs.list).mockResolvedValue([])
  vi.mocked(api.systemSettings.list).mockResolvedValue([])
})

async function expandResults() {
  const user = userEvent.setup()
  renderRepoScans()
  const expandBtn = await screen.findByRole('button', { name: /expand results/i })
  await user.click(expandBtn)
  return user
}

describe('RepoScans result row — risk count', () => {
  it('shows a risk count badge alongside the finding count', async () => {
    vi.mocked(api.repoScans.results).mockResolvedValue([{
      id: 10, repo_scan_id: 1, status: 'success', triggered_by: 'manual',
      pa_version: '0.7.0', finding_count: 1, findings: [{ package: 'flask' }],
      risks: [
        { package: 'reqeusts', ecosystem: 'pypi', score: 46, level: 'warning', signals: [] },
        { package: 'lodash-utils', ecosystem: 'npm', score: 20, level: 'info', signals: [] },
      ],
      sources: null, error_message: null, ecs_task_arn: null, notified: false,
      started_at: '2026-08-20T00:00:00Z', completed_at: '2026-08-20T00:01:00Z',
    }] as any)
    await expandResults()

    expect(await screen.findByText('1 finding')).toBeInTheDocument()
    expect(screen.getByText('2 risks')).toBeInTheDocument()
  })

  it('shows a "risks unavailable" marker, not silence, when risks is null', async () => {
    vi.mocked(api.repoScans.results).mockResolvedValue([{
      id: 11, repo_scan_id: 1, status: 'success', triggered_by: 'manual',
      pa_version: '0.7.0', finding_count: 1, findings: [{ package: 'flask' }], risks: null,
      sources: null, error_message: null, ecs_task_arn: null, notified: false,
      started_at: '2026-08-20T00:00:00Z', completed_at: '2026-08-20T00:01:00Z',
    }] as any)
    await expandResults()

    expect(await screen.findByText('1 finding')).toBeInTheDocument()
    expect(screen.getByText('risks unavailable')).toBeInTheDocument()
  })

  it('shows "0 risks", not unavailable, when risks is an explicit empty list', async () => {
    vi.mocked(api.repoScans.results).mockResolvedValue([{
      id: 12, repo_scan_id: 1, status: 'success', triggered_by: 'manual',
      pa_version: '0.7.0', finding_count: 1, findings: [{ package: 'flask' }], risks: [],
      sources: null, error_message: null, ecs_task_arn: null, notified: false,
      started_at: '2026-08-20T00:00:00Z', completed_at: '2026-08-20T00:01:00Z',
    }] as any)
    await expandResults()

    expect(await screen.findByText('1 finding')).toBeInTheDocument()
    expect(screen.getByText('0 risks')).toBeInTheDocument()
    expect(screen.queryByText('risks unavailable')).not.toBeInTheDocument()
  })

  it('shows an unscored warning when risk_failures > 0 even though risks is empty', async () => {
    vi.mocked(api.repoScans.results).mockResolvedValue([{
      id: 12, repo_scan_id: 1, status: 'success', triggered_by: 'manual',
      pa_version: '0.7.0', finding_count: 0, findings: [], risks: [], risk_failures: 3,
      sources: null, error_message: null, ecs_task_arn: null, notified: false,
      started_at: '2026-08-20T00:00:00Z', completed_at: '2026-08-20T00:01:00Z',
    }] as any)
    await expandResults()

    expect(await screen.findByText(/3 unscored/)).toBeInTheDocument()
  })

  it('does not show an unscored warning when risk_failures is 0', async () => {
    vi.mocked(api.repoScans.results).mockResolvedValue([{
      id: 13, repo_scan_id: 1, status: 'success', triggered_by: 'manual',
      pa_version: '0.7.0', finding_count: 0, findings: [], risks: [], risk_failures: 0,
      sources: null, error_message: null, ecs_task_arn: null, notified: false,
      started_at: '2026-08-20T00:00:00Z', completed_at: '2026-08-20T00:01:00Z',
    }] as any)
    await expandResults()

    await screen.findByRole('button', { name: /collapse results/i })
    expect(screen.queryByText(/unscored/)).not.toBeInTheDocument()
  })
})
