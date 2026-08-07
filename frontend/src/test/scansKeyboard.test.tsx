import { render, screen } from '@testing-library/react'
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

function renderScans() {
  return render(<MemoryRouter><Scans /></MemoryRouter>)
}

beforeEach(() => {
  vi.mocked(useAuth).mockReturnValue({ user: mockUser } as any)
  vi.mocked(api.hosts.list).mockResolvedValue([{ id: 10, name: 'host-a' }] as any)
  vi.mocked(api.repoScans.allResults).mockResolvedValue([])
})

describe('Tab bar keyboard navigation', () => {
  beforeEach(() => {
    vi.mocked(api.scans.list).mockResolvedValue([])
  })

  it('ArrowRight moves aria-selected and tabIndex to the next tab', async () => {
    const user = userEvent.setup()
    renderScans()
    const hostTab = await screen.findByRole('tab', { name: /host scans/i })
    const repoTab = screen.getByRole('tab', { name: /repo scans/i })

    expect(hostTab).toHaveAttribute('aria-selected', 'true')
    expect(hostTab).toHaveAttribute('tabindex', '0')
    expect(repoTab).toHaveAttribute('aria-selected', 'false')
    expect(repoTab).toHaveAttribute('tabindex', '-1')

    hostTab.focus()
    await user.keyboard('{ArrowRight}')

    expect(repoTab).toHaveAttribute('aria-selected', 'true')
    expect(repoTab).toHaveAttribute('tabindex', '0')
    expect(hostTab).toHaveAttribute('aria-selected', 'false')
    expect(hostTab).toHaveAttribute('tabindex', '-1')
  })

  it('ArrowLeft wraps around to the last tab from the first', async () => {
    const user = userEvent.setup()
    renderScans()
    const hostTab = await screen.findByRole('tab', { name: /host scans/i })
    const allTabs = screen.getAllByRole('tab')
    const lastTab = allTabs[allTabs.length - 1]

    hostTab.focus()
    await user.keyboard('{ArrowLeft}')

    expect(lastTab).toHaveAttribute('aria-selected', 'true')
    expect(hostTab).toHaveAttribute('aria-selected', 'false')
  })

  it('End moves to the last tab', async () => {
    const user = userEvent.setup()
    renderScans()
    const hostTab = await screen.findByRole('tab', { name: /host scans/i })
    const allTabs = screen.getAllByRole('tab')
    const lastTab = allTabs[allTabs.length - 1]

    hostTab.focus()
    await user.keyboard('{End}')

    expect(lastTab).toHaveAttribute('aria-selected', 'true')
    expect(lastTab).toHaveAttribute('tabindex', '0')
  })

  it('Home moves to the first tab from any position', async () => {
    const user = userEvent.setup()
    renderScans()
    const hostTab = await screen.findByRole('tab', { name: /host scans/i })
    const allTabs = screen.getAllByRole('tab')
    const lastTab = allTabs[allTabs.length - 1]

    hostTab.focus()
    await user.keyboard('{End}')
    expect(lastTab).toHaveAttribute('aria-selected', 'true')

    lastTab.focus()
    await user.keyboard('{Home}')
    expect(hostTab).toHaveAttribute('aria-selected', 'true')
    expect(hostTab).toHaveAttribute('tabindex', '0')
  })

  it('ArrowRight focuses the newly selected tab', async () => {
    const user = userEvent.setup()
    renderScans()
    const hostTab = await screen.findByRole('tab', { name: /host scans/i })
    const repoTab = screen.getByRole('tab', { name: /repo scans/i })

    hostTab.focus()
    await user.keyboard('{ArrowRight}')

    expect(document.activeElement).toBe(repoTab)
  })

  it('End focuses the last tab', async () => {
    const user = userEvent.setup()
    renderScans()
    const hostTab = await screen.findByRole('tab', { name: /host scans/i })
    const allTabs = screen.getAllByRole('tab')
    const lastTab = allTabs[allTabs.length - 1]

    hostTab.focus()
    await user.keyboard('{End}')

    expect(document.activeElement).toBe(lastTab)
  })

  it('ArrowRight wraps from the last tab back to the first', async () => {
    const user = userEvent.setup()
    renderScans()
    const hostTab = await screen.findByRole('tab', { name: /host scans/i })
    const repoTab = screen.getByRole('tab', { name: /repo scans/i })

    hostTab.focus()
    await user.keyboard('{End}')
    repoTab.focus()
    await user.keyboard('{ArrowRight}')

    expect(hostTab).toHaveAttribute('aria-selected', 'true')
    expect(document.activeElement).toBe(hostTab)
  })
})

describe('Scans row keyboard accessibility', () => {
  it('row with findings is focusable and announces expansion state', async () => {
    vi.mocked(api.scans.list).mockResolvedValue([
      { ...baseScan, id: 1, finding_count: 2, findings: [
        { severity: 'high', package: 'vuln-pkg', summary: 'Bad' },
      ]},
    ] as any)

    renderScans()
    const row = await screen.findByRole('button', { name: /\/app/i })
    expect(row).toHaveAttribute('tabindex', '0')
    expect(row).toHaveAttribute('aria-expanded', 'false')
  })

  it('Enter key expands a row that has findings', async () => {
    const user = userEvent.setup()
    vi.mocked(api.scans.list).mockResolvedValue([
      { ...baseScan, id: 1, finding_count: 1, findings: [
        { severity: 'high', package: 'vuln-pkg', summary: 'Bad thing' },
      ]},
    ] as any)

    renderScans()
    const row = await screen.findByRole('button', { name: /\/app/i })
    row.focus()
    await user.keyboard('{Enter}')
    expect(row).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText('vuln-pkg')).toBeInTheDocument()
  })

  it('Space key expands a row that has findings', async () => {
    const user = userEvent.setup()
    vi.mocked(api.scans.list).mockResolvedValue([
      { ...baseScan, id: 1, finding_count: 1, findings: [
        { severity: 'medium', package: 'space-pkg', summary: '' },
      ]},
    ] as any)

    renderScans()
    const row = await screen.findByRole('button', { name: /\/app/i })
    row.focus()
    await user.keyboard(' ')
    expect(row).toHaveAttribute('aria-expanded', 'true')
  })

  it('Enter key collapses an already-expanded row', async () => {
    const user = userEvent.setup()
    vi.mocked(api.scans.list).mockResolvedValue([
      { ...baseScan, id: 1, finding_count: 1, findings: [
        { severity: 'low', package: 'collapsible-pkg', summary: '' },
      ]},
    ] as any)

    renderScans()
    const row = await screen.findByRole('button', { name: /\/app/i })
    row.focus()
    await user.keyboard('{Enter}')
    expect(row).toHaveAttribute('aria-expanded', 'true')
    await user.keyboard('{Enter}')
    expect(row).toHaveAttribute('aria-expanded', 'false')
  })

  it('row without findings is not focusable and has no button role', async () => {
    vi.mocked(api.scans.list).mockResolvedValue([
      { ...baseScan, id: 1, finding_count: 0, findings: [] },
    ] as any)

    renderScans()
    await screen.findByText('/app')
    expect(screen.queryByRole('button', { name: /\/app/i })).toBeNull()
  })
})
