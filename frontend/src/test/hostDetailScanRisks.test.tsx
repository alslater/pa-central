import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router'
import { vi, beforeEach, describe, it, expect } from 'vitest'

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}))

vi.mock('@/lib/api', () => ({
  api: {
    hosts:   { get: vi.fn(), latestScans: vi.fn() },
    alerts:  { list: vi.fn() },
    configs: { list: vi.fn(), forHost: vi.fn() },
  },
}))

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import HostDetail from '@/pages/HostDetail'

const mockHost = {
  id: 1, name: 'web-01', hostname: 'web-01.local',
  daemon_status: 'running' as const, tags: [],
  last_seen_at: null, pa_version: null, description: null,
  daemon_uptime_seconds: null,
}

function renderHostDetail() {
  return render(
    <MemoryRouter initialEntries={['/hosts/1']}>
      <Routes>
        <Route path="/hosts/:id" element={<HostDetail />} />
      </Routes>
    </MemoryRouter>
  )
}

beforeEach(() => {
  vi.mocked(useAuth).mockReturnValue({ user: { id: 1, role: 'viewer' } } as any)
  vi.mocked(api.hosts.get).mockResolvedValue(mockHost as any)
  vi.mocked(api.alerts.list).mockResolvedValue([])
  vi.mocked(api.configs.list).mockResolvedValue([])
  vi.mocked(api.configs.forHost).mockResolvedValue(null)
})

async function openScansTab() {
  const user = userEvent.setup()
  renderHostDetail()
  const scansTab = await screen.findByRole('tab', { name: /scans/i })
  await user.click(scansTab)
  return user
}

describe('HostDetail scan row — risks', () => {
  it('a scan with risks but no findings is expandable and shows the risks table', async () => {
    vi.mocked(api.hosts.latestScans).mockResolvedValue([{
      id: 1, host_id: 1, project_path: '/app/riskyproject', scan_type: 'project',
      status: 'findings', finding_count: 0, findings: null,
      risks: [{ package: 'reqeusts', ecosystem: 'pypi', score: 46, level: 'warning',
                signals: [{ name: 'typosquat', score: 15, reason: "resembles 'requests'" }] }],
      sources: null, scanned_at: '2026-08-20T00:00:00Z', received_at: '2026-08-20T00:00:00Z',
    }] as any)
    const user = await openScansTab()

    const pathEl = await screen.findByText('/app/riskyproject')
    const row = pathEl.closest('.host-scan-card-row') as HTMLElement
    expect(row).toHaveAttribute('role', 'button')

    await user.click(row)
    expect(screen.getByText('reqeusts')).toBeInTheDocument()
  })

  it('shows a risk count badge alongside the finding count', async () => {
    vi.mocked(api.hosts.latestScans).mockResolvedValue([{
      id: 3, host_id: 1, project_path: '/app/multirisk', scan_type: 'project',
      status: 'findings', finding_count: 2, findings: [{ package: 'flask' }],
      risks: [
        { package: 'reqeusts', ecosystem: 'pypi', score: 46, level: 'warning', signals: [] },
        { package: 'lodash-utils', ecosystem: 'npm', score: 20, level: 'info', signals: [] },
      ],
      sources: null, scanned_at: '2026-08-20T00:00:00Z', received_at: '2026-08-20T00:00:00Z',
    }] as any)
    await openScansTab()

    await screen.findByText('/app/multirisk')
    expect(screen.getByText('2 findings')).toBeInTheDocument()
    expect(screen.getByText('2 risks')).toBeInTheDocument()
  })

  it('shows a "risks unavailable" marker, not silence, when risks is null', async () => {
    vi.mocked(api.hosts.latestScans).mockResolvedValue([{
      id: 4, host_id: 1, project_path: '/app/onlyfindings', scan_type: 'project',
      status: 'findings', finding_count: 1, findings: [{ package: 'flask' }], risks: null,
      sources: null, scanned_at: '2026-08-20T00:00:00Z', received_at: '2026-08-20T00:00:00Z',
    }] as any)
    await openScansTab()

    await screen.findByText('/app/onlyfindings')
    expect(screen.getByText('1 finding')).toBeInTheDocument()
    expect(screen.getByText('risks unavailable')).toBeInTheDocument()
  })

  it('shows "0 risks", not unavailable, when risks is an explicit empty list', async () => {
    vi.mocked(api.hosts.latestScans).mockResolvedValue([{
      id: 7, host_id: 1, project_path: '/app/cleanexplicit', scan_type: 'project',
      status: 'findings', finding_count: 1, findings: [{ package: 'flask' }], risks: [],
      sources: null, scanned_at: '2026-08-20T00:00:00Z', received_at: '2026-08-20T00:00:00Z',
    }] as any)
    await openScansTab()

    await screen.findByText('/app/cleanexplicit')
    expect(screen.getByText('0 risks')).toBeInTheDocument()
    expect(screen.queryByText('risks unavailable')).not.toBeInTheDocument()
  })

  it('shows an unscored warning when risk_failures is nonzero', async () => {
    vi.mocked(api.hosts.latestScans).mockResolvedValue([{
      id: 5, host_id: 1, project_path: '/app/partialscan', scan_type: 'project',
      status: 'findings', finding_count: 0, findings: null,
      risks: [], risk_failures: 2,
      sources: null, scanned_at: '2026-08-20T00:00:00Z', received_at: '2026-08-20T00:00:00Z',
    }] as any)
    await openScansTab()

    await screen.findByText('/app/partialscan')
    expect(screen.getByText(/⚠ 2 unscored/)).toBeInTheDocument()
  })

  it('does not show an unscored warning when risk_failures is zero', async () => {
    vi.mocked(api.hosts.latestScans).mockResolvedValue([{
      id: 6, host_id: 1, project_path: '/app/cleanriskscan', scan_type: 'project',
      status: 'findings', finding_count: 1, findings: [{ package: 'flask' }],
      risks: [], risk_failures: 0,
      sources: null, scanned_at: '2026-08-20T00:00:00Z', received_at: '2026-08-20T00:00:00Z',
    }] as any)
    await openScansTab()

    await screen.findByText('/app/cleanriskscan')
    expect(screen.queryByText(/unscored/)).not.toBeInTheDocument()
  })

  it('a scan with neither findings nor risks renders as a static, non-expandable row', async () => {
    vi.mocked(api.hosts.latestScans).mockResolvedValue([{
      id: 2, host_id: 1, project_path: '/app/cleanproject', scan_type: 'project',
      status: 'clean', finding_count: 0, findings: null, risks: null,
      sources: null, scanned_at: '2026-08-20T00:00:00Z', received_at: '2026-08-20T00:00:00Z',
    }] as any)
    await openScansTab()

    const pathEl = await screen.findByText('/app/cleanproject')
    const row = pathEl.closest('.host-scan-card-row') as HTMLElement
    expect(row).not.toHaveAttribute('role', 'button')
    expect(within(row).queryByRole('button')).not.toBeInTheDocument()
  })
})

describe('HostDetail scan row — rendering GET /hosts/{id}/latest-scans results', () => {
  // Grouping to one row per project_path and sorting alphabetically are now
  // done server-side (see TestHostLatestScans in backend/tests/test_hosts.py)
  // — GET /scans caps at 100 rows by default and is the package-alert CLI's
  // live surface, so client-side dedup against it could silently drop
  // projects once a host had more scans than that cap. The component now
  // renders whatever the endpoint returns, in the order it returns it.
  it('renders one card per row returned by the endpoint, in the given order', async () => {
    vi.mocked(api.hosts.latestScans).mockResolvedValue([
      { id: 1, host_id: 1, project_path: '/alpha', scan_type: 'project', status: 'clean',
        finding_count: 0, findings: null, risks: null, risk_failures: 0, sources: null,
        scanned_at: '2026-08-20T00:00:00Z', received_at: '2026-08-20T00:00:00Z' },
      { id: 2, host_id: 1, project_path: '/zeta', scan_type: 'project', status: 'clean',
        finding_count: 0, findings: null, risks: null, risk_failures: 0, sources: null,
        scanned_at: '2026-08-20T00:00:00Z', received_at: '2026-08-20T00:00:00Z' },
    ] as any)
    await openScansTab()

    await screen.findByText('/alpha')
    const paths = screen.getAllByText(/^\/(alpha|zeta)$/).map(el => el.textContent)
    expect(paths).toEqual(['/alpha', '/zeta'])
  })

  it('expanding one project card does not expand another', async () => {
    vi.mocked(api.hosts.latestScans).mockResolvedValue([
      { id: 1, host_id: 1, project_path: '/app/one', scan_type: 'project', status: 'findings',
        finding_count: 1, findings: [{ package: 'flask' }], risks: null, risk_failures: 0, sources: null,
        scanned_at: '2026-08-20T00:00:00Z', received_at: '2026-08-20T00:00:00Z' },
      { id: 2, host_id: 1, project_path: '/app/two', scan_type: 'project', status: 'findings',
        finding_count: 1, findings: [{ package: 'requests' }], risks: null, risk_failures: 0, sources: null,
        scanned_at: '2026-08-20T00:00:00Z', received_at: '2026-08-20T00:00:00Z' },
    ] as any)
    const user = await openScansTab()

    const oneEl = await screen.findByText('/app/one')
    const oneRow = oneEl.closest('.host-scan-card-row') as HTMLElement
    await user.click(oneRow)

    expect(screen.getByText('flask')).toBeInTheDocument()
    expect(screen.queryByText('requests')).not.toBeInTheDocument()
  })
})
