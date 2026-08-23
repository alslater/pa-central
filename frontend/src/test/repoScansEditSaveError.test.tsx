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

async function openSettings() {
  const user = userEvent.setup()
  renderRepoScans()
  const openBtn = await screen.findByRole('button', { name: /open settings for my-repo/i })
  await user.click(openBtn)
  return user
}

describe('RepoScans settings edit — save failure', () => {
  it('keeps the settings panel open and shows the error when save fails', async () => {
    vi.mocked(api.repoScans.update).mockRejectedValue(new Error('value is not a valid email address'))
    const user = await openSettings()

    const saveBtn = await screen.findByRole('button', { name: /^save$/i })
    await user.click(saveBtn)

    expect(await screen.findByText('value is not a valid email address')).toBeInTheDocument()
    // The settings form is still open — its Save button remains in the document.
    expect(screen.getByRole('button', { name: /^save$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /close settings for my-repo/i })).toBeInTheDocument()
  })

  it('closes the settings panel when save succeeds', async () => {
    vi.mocked(api.repoScans.update).mockResolvedValue({ ...mockScan } as any)
    const user = await openSettings()

    const saveBtn = await screen.findByRole('button', { name: /^save$/i })
    await user.click(saveBtn)

    expect(await screen.findByText('Saved')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^save$/i })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /open settings for my-repo/i })).toBeInTheDocument()
  })
})
