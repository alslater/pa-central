import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { vi, beforeEach, describe, it, expect } from 'vitest'

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}))

vi.mock('@/lib/api', () => ({
  api: {
    scans:    { list: vi.fn() },
    hosts:    { list: vi.fn() },
    repoScans: { allResults: vi.fn() },
  },
}))

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import { Scans } from '@/pages/Scans'

const mockUser = { id: 1, email: 'u@example.com', display_name: 'U', role: 'viewer' as const }

const baseScan = {
  id: 1,
  host_id: 10,
  project_path: '/app',
  scan_type: 'npm',
  status: 'pass' as const,
  finding_count: 0,
  scanned_at: new Date().toISOString(),
  sources: [],
}

const baseRepoResult = {
  id: 1,
  repo_scan_id: 1,
  status: 'success' as const,
  triggered_by: 'manual' as const,
  pa_version: '0.7.0',
  finding_count: 0,
  findings: null,
  sources: null,
  error_message: null,
  ecs_task_arn: null,
  notified: false,
  started_at: new Date().toISOString(),
  completed_at: new Date().toISOString(),
  scan_name: 'my-repo',
  scan_url: 'https://github.com/example/my-repo',
  scan_breach: false,
  scan_breach_count: 0,
}

function renderScans() {
  return render(<MemoryRouter><Scans /></MemoryRouter>)
}

beforeEach(() => {
  vi.mocked(useAuth).mockReturnValue({ user: mockUser } as any)
  vi.mocked(api.hosts.list).mockResolvedValue([{ id: 10, name: 'host-a' }] as any)
})

const mockRisk = { package: 'reqeusts', ecosystem: 'pypi', score: 46, level: 'warning',
  signals: [{ name: 'typosquat', score: 15, reason: "resembles 'requests'" }] }

describe('Scans page — host scans table risk column', () => {
  beforeEach(() => {
    vi.mocked(api.repoScans.allResults).mockResolvedValue([])
  })

  it('shows the Risks column header', async () => {
    vi.mocked(api.scans.list).mockResolvedValue([{ ...baseScan, findings: [], risks: [] }] as any)
    renderScans()
    expect(await screen.findByRole('columnheader', { name: 'Risks' })).toBeInTheDocument()
  })

  it('shows the risk count for a scan with risks but no findings', async () => {
    vi.mocked(api.scans.list).mockResolvedValue([
      { ...baseScan, finding_count: 0, findings: [], risks: [mockRisk] },
    ] as any)
    renderScans()

    const path = await screen.findByText('/app')
    const row = path.closest('tr') as HTMLElement
    expect(row).toHaveAttribute('role', 'button')
    const risksCell = within(row).getAllByRole('cell')[4]
    expect(within(risksCell).getByText('1')).toBeInTheDocument()
  })

  it('a scan with risks but no findings is expandable and reveals the risks table', async () => {
    const user = userEvent.setup()
    vi.mocked(api.scans.list).mockResolvedValue([
      { ...baseScan, finding_count: 0, findings: [], risks: [mockRisk] },
    ] as any)
    renderScans()

    const row = await screen.findByRole('button', { name: /\/app/i })
    await user.click(row)
    expect(screen.getByText('reqeusts')).toBeInTheDocument()
  })

  it('a scan with neither findings nor risks is not a button', async () => {
    vi.mocked(api.scans.list).mockResolvedValue([
      { ...baseScan, finding_count: 0, findings: [], risks: [] },
    ] as any)
    renderScans()

    await screen.findByText('/app')
    expect(screen.queryByRole('button', { name: /\/app/i })).toBeNull()
  })

  it('shows an unscored warning when risk_failures > 0 even though risks is empty', async () => {
    vi.mocked(api.scans.list).mockResolvedValue([
      { ...baseScan, finding_count: 0, findings: [], risks: [], risk_failures: 2 },
    ] as any)
    renderScans()

    await screen.findByText('/app')
    // The warning must be visible text, not only a `title` tooltip — those
    // are unreachable to keyboard and touch users.
    expect(screen.getByText(/⚠ 2 unscored/)).toBeInTheDocument()
  })

  it('does not show an unscored warning when risk_failures is 0', async () => {
    vi.mocked(api.scans.list).mockResolvedValue([
      { ...baseScan, finding_count: 0, findings: [], risks: [], risk_failures: 0 },
    ] as any)
    renderScans()

    await screen.findByText('/app')
    expect(screen.queryByText(/⚠/)).not.toBeInTheDocument()
  })

  it('shows an unavailable marker, not 0, when risks is null (no risk pass reported)', async () => {
    vi.mocked(api.scans.list).mockResolvedValue([
      { ...baseScan, finding_count: 0, findings: [], risks: null },
    ] as any)
    renderScans()

    const path = await screen.findByText('/app')
    const row = path.closest('tr') as HTMLElement
    const risksCell = within(row).getAllByRole('cell')[4]
    expect(within(risksCell).getByText('—')).toBeInTheDocument()
    expect(within(risksCell).queryByText('0')).not.toBeInTheDocument()
  })

  it('shows 0, not an unavailable marker, when risks is an explicit empty list', async () => {
    vi.mocked(api.scans.list).mockResolvedValue([
      { ...baseScan, finding_count: 0, findings: [], risks: [] },
    ] as any)
    renderScans()

    const path = await screen.findByText('/app')
    const row = path.closest('tr') as HTMLElement
    const risksCell = within(row).getAllByRole('cell')[4]
    expect(within(risksCell).getByText('0')).toBeInTheDocument()
    expect(within(risksCell).queryByText('—')).not.toBeInTheDocument()
  })
})

describe('Scans page — repo scans table risk column', () => {
  beforeEach(() => {
    vi.mocked(api.scans.list).mockResolvedValue([])
  })

  it('shows the Risks column header and risk count', async () => {
    const user = userEvent.setup()
    vi.mocked(api.repoScans.allResults).mockResolvedValue([
      { ...baseRepoResult, finding_count: 0, findings: [], risks: [mockRisk] },
    ] as any)
    renderScans()

    const repoTab = await screen.findByRole('tab', { name: /repo scans/i })
    await user.click(repoTab)

    expect(screen.getByRole('columnheader', { name: 'Risks' })).toBeInTheDocument()
    const name = screen.getByText('my-repo')
    const row = name.closest('tr') as HTMLElement
    expect(row).toHaveAttribute('role', 'button')
    const risksCell = within(row).getAllByRole('cell')[4]
    expect(within(risksCell).getByText('1')).toBeInTheDocument()

    await user.click(row)
    expect(screen.getByText('reqeusts')).toBeInTheDocument()
  })

  it('a repo result with neither findings nor risks is not a button', async () => {
    const user = userEvent.setup()
    vi.mocked(api.repoScans.allResults).mockResolvedValue([
      { ...baseRepoResult, finding_count: 0, findings: [], risks: [] },
    ] as any)
    renderScans()

    const repoTab = await screen.findByRole('tab', { name: /repo scans/i })
    await user.click(repoTab)

    await screen.findByText('my-repo')
    expect(screen.queryByRole('button', { name: /my-repo/i })).toBeNull()
  })

  it('shows an unscored warning when risk_failures > 0 even though risks is empty', async () => {
    const user = userEvent.setup()
    vi.mocked(api.repoScans.allResults).mockResolvedValue([
      { ...baseRepoResult, finding_count: 0, findings: [], risks: [], risk_failures: 2 },
    ] as any)
    renderScans()

    const repoTab = await screen.findByRole('tab', { name: /repo scans/i })
    await user.click(repoTab)

    // The warning must be visible text, not only a `title` tooltip — those
    // are unreachable to keyboard and touch users.
    expect(await screen.findByText(/⚠ 2 unscored/)).toBeInTheDocument()
  })

  it('does not show an unscored warning when risk_failures is 0', async () => {
    const user = userEvent.setup()
    vi.mocked(api.repoScans.allResults).mockResolvedValue([
      { ...baseRepoResult, finding_count: 0, findings: [], risks: [], risk_failures: 0 },
    ] as any)
    renderScans()

    const repoTab = await screen.findByRole('tab', { name: /repo scans/i })
    await user.click(repoTab)

    await screen.findByText('my-repo')
    expect(screen.queryByText(/⚠/)).not.toBeInTheDocument()
  })

  it('shows an unavailable marker, not 0, when risks is null (no risk pass reported)', async () => {
    vi.mocked(api.repoScans.allResults).mockResolvedValue([
      { ...baseRepoResult, finding_count: 0, findings: [], risks: null },
    ] as any)
    renderScans()

    const repoTab = await screen.findByRole('tab', { name: /repo scans/i })
    await userEvent.setup().click(repoTab)

    const name = await screen.findByText('my-repo')
    const row = name.closest('tr') as HTMLElement
    const risksCell = within(row).getAllByRole('cell')[4]
    expect(within(risksCell).getByText('—')).toBeInTheDocument()
    expect(within(risksCell).queryByText('0')).not.toBeInTheDocument()
  })

  it('shows 0, not an unavailable marker, when risks is an explicit empty list', async () => {
    vi.mocked(api.repoScans.allResults).mockResolvedValue([
      { ...baseRepoResult, finding_count: 0, findings: [], risks: [] },
    ] as any)
    renderScans()

    const repoTab = await screen.findByRole('tab', { name: /repo scans/i })
    await userEvent.setup().click(repoTab)

    const name = await screen.findByText('my-repo')
    const row = name.closest('tr') as HTMLElement
    const risksCell = within(row).getAllByRole('cell')[4]
    expect(within(risksCell).getByText('0')).toBeInTheDocument()
    expect(within(risksCell).queryByText('—')).not.toBeInTheDocument()
  })
})
