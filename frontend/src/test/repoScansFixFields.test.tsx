import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { vi, beforeEach, describe, it, expect } from 'vitest'

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}))

vi.mock('@/hooks/useLiveAlerts', () => ({
  useLiveAlertsContext: () => ({
    count: 0, clear: vi.fn(), Toast: null, registerPendingOp: vi.fn(), getSessionEpoch: () => 0,
  }),
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
    repoCredentials: { list: vi.fn(), create: vi.fn() },
    configs:         { list: vi.fn() },
    systemSettings:  { list: vi.fn() },
  },
}))

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import RepoScans from '@/pages/RepoScans'

const mockUser = { id: 1, email: 'u@example.com', display_name: 'U', role: 'admin' as const }

function renderRepoScans() {
  return render(<MemoryRouter><RepoScans /></MemoryRouter>)
}

const gitCred = { id: 1, name: 'github', credential_type: 'https_token', index_url: null, index_username: null,
  created_at: '', updated_at: '' }
const idxCred = { id: 2, name: 'internal-pypi', credential_type: 'package_index',
  index_url: 'https://pypi.internal.example/simple', index_username: 'reader', created_at: '', updated_at: '' }

describe('fix-plan fields', () => {
  beforeEach(() => {
    vi.mocked(useAuth).mockReturnValue({ user: mockUser } as any)
    vi.mocked(api.repoCredentials.list).mockResolvedValue([gitCred, idxCred] as any)
    vi.mocked(api.repoScans.list).mockResolvedValue([] as any)
    vi.mocked(api.configs.list).mockResolvedValue([])
    vi.mocked(api.systemSettings.list).mockResolvedValue([])
  })

  it('shows the package index credential type label', async () => {
    renderRepoScans()
    await userEvent.click(await screen.findByRole('tab', { name: /credentials/i }))
    expect(await screen.findByText('Package index (uv)')).toBeInTheDocument()
  })

  it('creates a scan with fix plans and a package index, and keeps it out of the git picker', async () => {
    vi.mocked(api.repoScans.create).mockResolvedValue({} as any)
    renderRepoScans()
    await userEvent.click(await screen.findByRole('button', { name: /add scan/i }))
    await userEvent.type(screen.getByLabelText('Name'), 's')
    await userEvent.type(screen.getByLabelText('URL'), 'https://github.com/x/s')
    const gitPicker = screen.getByLabelText('Credential')
    expect(within(gitPicker).queryByRole('option', { name: 'internal-pypi' })).toBeNull()
    await userEvent.click(screen.getByLabelText(/generate fix plans/i))
    await userEvent.click(screen.getByLabelText('internal-pypi'))
    await userEvent.click(screen.getByRole('button', { name: 'Create' }))
    expect(api.repoScans.create).toHaveBeenCalledWith(expect.objectContaining({
      fix_plans_enabled: true, package_index_credential_ids: [2],
    }))
  })

  it('warns that the registry token is readable by repository code', async () => {
    renderRepoScans()
    await userEvent.click(await screen.findByRole('button', { name: /add scan/i }))
    await userEvent.click(screen.getByLabelText(/generate fix plans/i))
    expect(screen.getByText(/read-only tokens/i)).toBeInTheDocument()
  })

  it('hides the registry fieldset until fix plans is ticked', async () => {
    renderRepoScans()
    await userEvent.click(await screen.findByRole('button', { name: /add scan/i }))
    expect(screen.queryByText('Package index credentials')).toBeNull()
    await userEvent.click(screen.getByLabelText(/generate fix plans/i))
    expect(screen.getByText('Package index credentials')).toBeInTheDocument()
  })

  it('says where to add a package index credential when there is none', async () => {
    vi.mocked(api.repoCredentials.list).mockResolvedValue([gitCred] as any)
    renderRepoScans()
    await userEvent.click(await screen.findByRole('button', { name: /add scan/i }))
    await userEvent.click(screen.getByLabelText(/generate fix plans/i))
    expect(screen.getByText(/add one on the Credentials tab/i)).toBeInTheDocument()
    expect(screen.queryByText(/read-only tokens/i)).toBeNull()
  })

  it('edit form keeps linked indexes when fix plans is unticked', async () => {
    vi.mocked(api.repoScans.list).mockResolvedValue([{
      id: 1, name: 'my-repo', url: 'https://github.com/example/my-repo', branch: 'main',
      cron_schedule: null, cron_timezone: null, is_enabled: true, credential_id: null,
      config_template_id: null, pa_version: null, scan_flags: null, subfolder: null,
      sla_high_days: null, sla_medium_days: null, min_notify_severity: 'medium',
      notify_recipients: [], last_scan_at: null, created_at: '', updated_at: '', created_by_id: 1,
      breach: false, breach_count: 0, scan_config_hash: null,
      fix_plans_enabled: true, package_index_credential_ids: [2],
    }] as any)
    vi.mocked(api.repoScans.update).mockResolvedValue({} as any)
    renderRepoScans()
    await userEvent.click(await screen.findByRole('button', { name: /open settings for my-repo/i }))
    expect(screen.getByLabelText('internal-pypi')).toBeChecked()
    await userEvent.click(screen.getByLabelText(/generate fix plans/i))
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(api.repoScans.update).toHaveBeenCalledWith(1, expect.objectContaining({
      fix_plans_enabled: false, package_index_credential_ids: [2],
    }))
  })
})

describe('credential form', () => {
  beforeEach(() => {
    vi.mocked(api.repoCredentials.create).mockReset()
    vi.mocked(useAuth).mockReturnValue({ user: mockUser } as any)
    vi.mocked(api.repoCredentials.list).mockResolvedValue([])
    vi.mocked(api.repoScans.list).mockResolvedValue([] as any)
    vi.mocked(api.configs.list).mockResolvedValue([])
    vi.mocked(api.systemSettings.list).mockResolvedValue([])
  })

  async function openForm() {
    renderRepoScans()
    await userEvent.click(await screen.findByRole('tab', { name: /credentials/i }))
    await userEvent.click(await screen.findByRole('button', { name: /add credential/i }))
  }

  it('sends index fields for package_index, switches the secret label, and shows the note', async () => {
    vi.mocked(api.repoCredentials.create).mockResolvedValue({} as any)
    await openForm()
    await userEvent.type(screen.getByLabelText('Name'), 'idx')
    await userEvent.selectOptions(screen.getByLabelText('Type'), 'package_index')
    expect(screen.getByText(/read-only token scoped to the registry/i)).toBeInTheDocument()
    expect(screen.getByLabelText('Token')).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText('Index URL'), 'https://p.example/simple')
    await userEvent.type(screen.getByLabelText(/Username/), 'reader')
    expect(screen.getByLabelText('Password')).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText('Password'), 'pw')
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(api.repoCredentials.create).toHaveBeenCalledWith(expect.objectContaining({
      credential_type: 'package_index', index_url: 'https://p.example/simple', index_username: 'reader',
    }))
  })

  it('sends neither index field for an https_token credential', async () => {
    vi.mocked(api.repoCredentials.create).mockResolvedValue({} as any)
    await openForm()
    await userEvent.type(screen.getByLabelText('Name'), 'gh')
    await userEvent.selectOptions(screen.getByLabelText('Type'), 'https_token')
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    const sent = vi.mocked(api.repoCredentials.create).mock.lastCall![0]
    expect(sent).not.toHaveProperty('index_url')
    expect(sent).not.toHaveProperty('index_username')
    expect(screen.queryByText(/read-only token scoped/i)).toBeNull()
  })
})
