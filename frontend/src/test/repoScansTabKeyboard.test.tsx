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

const mockUser = { id: 1, email: 'u@example.com', display_name: 'U', role: 'viewer' as const }

function renderRepoScans() {
  return render(<MemoryRouter><RepoScans /></MemoryRouter>)
}

beforeEach(() => {
  vi.mocked(useAuth).mockReturnValue({ user: mockUser } as any)
  vi.mocked(api.repoScans.list).mockResolvedValue([])
  vi.mocked(api.repoCredentials.list).mockResolvedValue([])
  vi.mocked(api.configs.list).mockResolvedValue([])
  vi.mocked(api.systemSettings.list).mockResolvedValue([])
})

describe('RepoScans tab bar keyboard navigation', () => {

  it('renders both tabs with correct initial ARIA state', async () => {
    renderRepoScans()
    const scansTab = await screen.findByRole('tab', { name: /repo scans/i })
    const credsTab = screen.getByRole('tab', { name: /credentials/i })

    expect(scansTab).toHaveAttribute('aria-selected', 'true')
    expect(scansTab).toHaveAttribute('tabindex', '0')
    expect(credsTab).toHaveAttribute('aria-selected', 'false')
    expect(credsTab).toHaveAttribute('tabindex', '-1')
  })

  it('ArrowRight moves aria-selected and tabIndex to the next tab', async () => {
    const user = userEvent.setup()
    renderRepoScans()
    const scansTab = await screen.findByRole('tab', { name: /repo scans/i })
    const credsTab = screen.getByRole('tab', { name: /credentials/i })

    scansTab.focus()
    await user.keyboard('{ArrowRight}')

    expect(credsTab).toHaveAttribute('aria-selected', 'true')
    expect(credsTab).toHaveAttribute('tabindex', '0')
    expect(scansTab).toHaveAttribute('aria-selected', 'false')
    expect(scansTab).toHaveAttribute('tabindex', '-1')
  })

  it('ArrowLeft wraps from the first tab to the last', async () => {
    const user = userEvent.setup()
    renderRepoScans()
    const scansTab = await screen.findByRole('tab', { name: /repo scans/i })
    const credsTab = screen.getByRole('tab', { name: /credentials/i })

    scansTab.focus()
    await user.keyboard('{ArrowLeft}')

    expect(credsTab).toHaveAttribute('aria-selected', 'true')
    expect(scansTab).toHaveAttribute('aria-selected', 'false')
  })

  it('End moves to the last tab', async () => {
    const user = userEvent.setup()
    renderRepoScans()
    const scansTab = await screen.findByRole('tab', { name: /repo scans/i })
    const credsTab = screen.getByRole('tab', { name: /credentials/i })

    scansTab.focus()
    await user.keyboard('{End}')

    expect(credsTab).toHaveAttribute('aria-selected', 'true')
    expect(credsTab).toHaveAttribute('tabindex', '0')
  })

  it('Home moves back to the first tab', async () => {
    const user = userEvent.setup()
    renderRepoScans()
    const scansTab = await screen.findByRole('tab', { name: /repo scans/i })
    const credsTab = screen.getByRole('tab', { name: /credentials/i })

    scansTab.focus()
    await user.keyboard('{End}')
    expect(credsTab).toHaveAttribute('aria-selected', 'true')

    credsTab.focus()
    await user.keyboard('{Home}')

    expect(scansTab).toHaveAttribute('aria-selected', 'true')
    expect(scansTab).toHaveAttribute('tabindex', '0')
  })

  it('ArrowRight focuses the newly selected tab', async () => {
    const user = userEvent.setup()
    renderRepoScans()
    const scansTab = await screen.findByRole('tab', { name: /repo scans/i })
    const credsTab = screen.getByRole('tab', { name: /credentials/i })

    scansTab.focus()
    await user.keyboard('{ArrowRight}')

    expect(document.activeElement).toBe(credsTab)
  })

  it('ArrowRight wraps from last tab back to the first', async () => {
    const user = userEvent.setup()
    renderRepoScans()
    const scansTab = await screen.findByRole('tab', { name: /repo scans/i })
    const credsTab = screen.getByRole('tab', { name: /credentials/i })

    scansTab.focus()
    await user.keyboard('{End}')
    credsTab.focus()
    await user.keyboard('{ArrowRight}')

    expect(scansTab).toHaveAttribute('aria-selected', 'true')
    expect(document.activeElement).toBe(scansTab)
  })
})
