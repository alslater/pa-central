import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { vi, beforeEach, describe, it, expect } from 'vitest'

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}))

vi.mock('@/lib/api', () => ({
  api: {
    hosts:   { get: vi.fn() },
    alerts:  { list: vi.fn() },
    scans:   { list: vi.fn() },
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
  vi.mocked(api.scans.list).mockResolvedValue([])
  vi.mocked(api.configs.list).mockResolvedValue([])
  vi.mocked(api.configs.forHost).mockResolvedValue(null)
})

describe('HostDetail tab bar keyboard navigation', () => {

  it('renders all three tabs with correct initial ARIA state', async () => {
    renderHostDetail()
    const alertsTab = await screen.findByRole('tab', { name: /alerts/i })
    const scansTab  = screen.getByRole('tab', { name: /scans/i })
    const configTab = screen.getByRole('tab', { name: /config/i })

    expect(alertsTab).toHaveAttribute('aria-selected', 'true')
    expect(alertsTab).toHaveAttribute('tabindex', '0')
    expect(scansTab).toHaveAttribute('aria-selected', 'false')
    expect(scansTab).toHaveAttribute('tabindex', '-1')
    expect(configTab).toHaveAttribute('aria-selected', 'false')
    expect(configTab).toHaveAttribute('tabindex', '-1')
  })

  it('ArrowRight moves selection and tabIndex to the next tab', async () => {
    const user = userEvent.setup()
    renderHostDetail()
    const alertsTab = await screen.findByRole('tab', { name: /alerts/i })
    const scansTab  = screen.getByRole('tab', { name: /scans/i })

    alertsTab.focus()
    await user.keyboard('{ArrowRight}')

    expect(scansTab).toHaveAttribute('aria-selected', 'true')
    expect(scansTab).toHaveAttribute('tabindex', '0')
    expect(alertsTab).toHaveAttribute('aria-selected', 'false')
    expect(alertsTab).toHaveAttribute('tabindex', '-1')
  })

  it('ArrowLeft wraps from the first tab to the last', async () => {
    const user = userEvent.setup()
    renderHostDetail()
    const alertsTab = await screen.findByRole('tab', { name: /alerts/i })
    const configTab = screen.getByRole('tab', { name: /config/i })

    alertsTab.focus()
    await user.keyboard('{ArrowLeft}')

    expect(configTab).toHaveAttribute('aria-selected', 'true')
    expect(alertsTab).toHaveAttribute('aria-selected', 'false')
  })

  it('End moves to the last tab', async () => {
    const user = userEvent.setup()
    renderHostDetail()
    const alertsTab = await screen.findByRole('tab', { name: /alerts/i })
    const configTab = screen.getByRole('tab', { name: /config/i })

    alertsTab.focus()
    await user.keyboard('{End}')

    expect(configTab).toHaveAttribute('aria-selected', 'true')
    expect(configTab).toHaveAttribute('tabindex', '0')
  })

  it('Home moves back to the first tab', async () => {
    const user = userEvent.setup()
    renderHostDetail()
    const alertsTab = await screen.findByRole('tab', { name: /alerts/i })
    const configTab = screen.getByRole('tab', { name: /config/i })

    alertsTab.focus()
    await user.keyboard('{End}')
    configTab.focus()
    await user.keyboard('{Home}')

    expect(alertsTab).toHaveAttribute('aria-selected', 'true')
    expect(alertsTab).toHaveAttribute('tabindex', '0')
  })

  it('ArrowRight focuses the newly selected tab', async () => {
    const user = userEvent.setup()
    renderHostDetail()
    const alertsTab = await screen.findByRole('tab', { name: /alerts/i })
    const scansTab  = screen.getByRole('tab', { name: /scans/i })

    alertsTab.focus()
    await user.keyboard('{ArrowRight}')

    expect(document.activeElement).toBe(scansTab)
  })

  it('ArrowRight wraps from the last tab back to the first', async () => {
    const user = userEvent.setup()
    renderHostDetail()
    const alertsTab = await screen.findByRole('tab', { name: /alerts/i })
    const configTab = screen.getByRole('tab', { name: /config/i })

    alertsTab.focus()
    await user.keyboard('{End}')
    configTab.focus()
    await user.keyboard('{ArrowRight}')

    expect(alertsTab).toHaveAttribute('aria-selected', 'true')
    expect(document.activeElement).toBe(alertsTab)
  })
})
