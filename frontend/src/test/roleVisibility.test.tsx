/**
 * Role-based UI visibility tests.
 *
 * Verifies that action buttons (delete, ack, assign, etc.) are shown or hidden
 * according to the current user's role, matching the backend permission model:
 *   admin    — all actions
 *   operator — operator+ actions, NOT admin-only (delete host, delete scan…)
 *   viewer   — no write actions
 */
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { vi, beforeEach, describe, it, expect } from 'vitest'
import type { User } from '@/lib/api'

// ── Module mocks (hoisted) ────────────────────────────────────────────────────

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}))

vi.mock('@/lib/api', () => ({
  api: {
    hosts:           { list: vi.fn() },
    alerts:          { list: vi.fn() },
    cooldown:        { list: vi.fn() },
    configs:         { list: vi.fn(), forHost: vi.fn() },
    repoScans: {
      list:        vi.fn(),
      results:     vi.fn(),
      scanOptions: vi.fn().mockResolvedValue({ flags: [], exclusions: [] }),
      create:      vi.fn(),
      update:      vi.fn(),
      delete:      vi.fn(),
      trigger:     vi.fn(),
    },
    repoCredentials: { list: vi.fn() },
    systemSettings:  { list: vi.fn() },
    users:           { list: vi.fn() },
  },
}))

// ── Imports (after mocks) ─────────────────────────────────────────────────────

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import Hosts from '@/pages/Hosts'
import Alerts from '@/pages/Alerts'
import Cooldown from '@/pages/Cooldown'
import Configs from '@/pages/Configs'
import Users from '@/pages/Users'
import RepoScans from '@/pages/RepoScans'
import SystemSettings from '@/pages/SystemSettings'

// ── Helpers ────────────────────────────────────────────────────────────────────

function mockUser(role: User['role']): User {
  return {
    id: 1, email: 'test@example.com', display_name: 'Test', role,
    is_active: true, totp_enabled: false, created_at: '2024-01-01T00:00:00Z',
  }
}

function setRole(role: User['role'] | null) {
  vi.mocked(useAuth).mockReturnValue({
    user: role ? mockUser(role) : null,
    loading: false,
    login: vi.fn(),
    completeTotp: vi.fn(),
    logout: vi.fn(),
  })
}

function renderPage(ui: React.ReactElement) {
  // Stub fetch so Shell's SSE alert stream doesn't throw
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, body: null }))
  return render(<MemoryRouter>{ui}</MemoryRouter>)
}

// ── Hosts ──────────────────────────────────────────────────────────────────────

describe('Hosts page — delete button', () => {
  const host = {
    id: 1, name: 'web-01', hostname: 'web-01.local',
    daemon_status: 'running' as const, tags: [],
    last_seen_at: null, pa_version: null, description: null,
    daemon_uptime_seconds: null,
  }

  beforeEach(() => {
    vi.mocked(api.hosts.list).mockResolvedValue([host] as any)
  })

  it('shows delete button for admin', async () => {
    setRole('admin')
    renderPage(<Hosts />)
    expect(await screen.findByRole('button', { name: /delete web-01/i })).toBeInTheDocument()
  })

  it('hides delete button for operator', async () => {
    setRole('operator')
    renderPage(<Hosts />)
    await screen.findByText('web-01')
    expect(screen.queryByRole('button', { name: /delete web-01/i })).not.toBeInTheDocument()
  })

  it('hides delete button for viewer', async () => {
    setRole('viewer')
    renderPage(<Hosts />)
    await screen.findByText('web-01')
    expect(screen.queryByRole('button', { name: /delete web-01/i })).not.toBeInTheDocument()
  })
})

// ── Alerts ─────────────────────────────────────────────────────────────────────

describe('Alerts page — acknowledge buttons', () => {
  const alert = {
    id: 1, package_name: 'lodash', ecosystem: 'npm', kind: 'osv',
    severity: 'high' as const, acknowledged: false,
    host_id: 1, received_at: '2024-01-01T00:00:00Z',
    advisory_id: null, project_path: null, package_version: null,
  }

  beforeEach(() => {
    vi.mocked(api.alerts.list).mockResolvedValue([alert] as any)
  })

  it('shows Ack button and Acknowledge all for operator', async () => {
    setRole('operator')
    renderPage(<Alerts />)
    expect(await screen.findByRole('button', { name: /acknowledge all/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^ack$/i })).toBeInTheDocument()
  })

  it('shows Ack button and Acknowledge all for admin', async () => {
    setRole('admin')
    renderPage(<Alerts />)
    expect(await screen.findByRole('button', { name: /acknowledge all/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^ack$/i })).toBeInTheDocument()
  })

  it('hides Ack button and Acknowledge all for viewer', async () => {
    setRole('viewer')
    renderPage(<Alerts />)
    await screen.findByText('lodash')
    expect(screen.queryByRole('button', { name: /acknowledge all/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^ack$/i })).not.toBeInTheDocument()
  })
})

// ── Cooldown ───────────────────────────────────────────────────────────────────

describe('Cooldown page — delete button', () => {
  const entry = {
    id: 1, package_name: 'requests', ecosystem: 'pypi', host_id: null,
    package_version: null, note: null, expires_at: null,
    created_at: '2024-01-01T00:00:00Z',
  }

  beforeEach(() => {
    vi.mocked(api.cooldown.list).mockResolvedValue([entry] as any)
    vi.mocked(api.hosts.list).mockResolvedValue([])
  })

  it('shows delete button for operator', async () => {
    setRole('operator')
    renderPage(<Cooldown />)
    expect(await screen.findByRole('button', { name: /delete requests/i })).toBeInTheDocument()
  })

  it('shows delete button for admin', async () => {
    setRole('admin')
    renderPage(<Cooldown />)
    expect(await screen.findByRole('button', { name: /delete requests/i })).toBeInTheDocument()
  })

  it('hides delete button for viewer', async () => {
    setRole('viewer')
    renderPage(<Cooldown />)
    await screen.findByText('requests')
    expect(screen.queryByRole('button', { name: /delete requests/i })).not.toBeInTheDocument()
  })
})

// ── Configs ────────────────────────────────────────────────────────────────────

describe('Configs page — assign and delete template buttons', () => {
  const template = {
    id: 1, name: 'default', toml_content: '[section]\nkey = "val"',
    description: null, is_default: false, updated_at: '2024-01-01T00:00:00Z',
  }

  beforeEach(() => {
    vi.mocked(api.configs.list).mockResolvedValue([template] as any)
    vi.mocked(api.hosts.list).mockResolvedValue([])
  })

  it('shows assign and delete for admin', async () => {
    setRole('admin')
    renderPage(<Configs />)
    // click the template to select it
    ;(await screen.findByText('default')).click()
    expect(await screen.findByRole('button', { name: /assign to host/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /delete template/i })).toBeInTheDocument()
  })

  it('shows assign but NOT delete for operator', async () => {
    setRole('operator')
    renderPage(<Configs />)
    ;(await screen.findByText('default')).click()
    expect(await screen.findByRole('button', { name: /assign to host/i })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /delete template/i })).not.toBeInTheDocument()
  })

  it('hides both assign and delete for viewer', async () => {
    // viewers hit the developer path: hosts.list() → [] → no templates shown
    setRole('viewer')
    renderPage(<Configs />)
    // wait for the page to finish loading (empty state appears)
    await screen.findByText(/no templates yet/i)
    expect(screen.queryByRole('button', { name: /assign to host/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /delete template/i })).not.toBeInTheDocument()
  })
})

// ── Users ──────────────────────────────────────────────────────────────────────

describe('Users page — add user button', () => {
  beforeEach(() => {
    vi.mocked(api.users.list).mockResolvedValue([])
  })

  it('shows Add user for admin', async () => {
    setRole('admin')
    renderPage(<Users />)
    expect(await screen.findByRole('button', { name: /add user/i })).toBeInTheDocument()
  })

  it('hides Add user for operator', async () => {
    setRole('operator')
    renderPage(<Users />)
    await screen.findByText(/manage access/i)
    expect(screen.queryByRole('button', { name: /add user/i })).not.toBeInTheDocument()
  })
})

// ── RepoScans ──────────────────────────────────────────────────────────────────

describe('RepoScans page — action buttons', () => {
  const scan = {
    id: 1, name: 'api-repo', url: 'https://github.com/org/api', branch: 'main',
    is_enabled: true, cron_schedule: null, cron_timezone: null,
    credential_id: null, config_template_id: null, pa_version: null,
    scan_flags: null, subfolder: null, min_notify_severity: 'medium' as const,
    notify_recipients: [], last_scan_at: null,
    created_at: '2024-01-01T00:00:00Z',
  }

  beforeEach(() => {
    vi.mocked(api.repoScans.list).mockResolvedValue([scan] as any)
    vi.mocked(api.repoCredentials.list).mockResolvedValue([])
    vi.mocked(api.configs.list).mockResolvedValue([])
    vi.mocked(api.systemSettings.list).mockResolvedValue([])
  })

  it('shows trigger, settings, delete and Add scan for admin', async () => {
    setRole('admin')
    renderPage(<RepoScans />)
    expect(await screen.findByRole('button', { name: /trigger api-repo/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /open settings for api-repo/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /delete api-repo/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /add scan/i })).toBeInTheDocument()
  })

  it('shows trigger and settings but NOT delete for operator', async () => {
    setRole('operator')
    renderPage(<RepoScans />)
    expect(await screen.findByRole('button', { name: /trigger api-repo/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /open settings for api-repo/i })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /delete api-repo/i })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /add scan/i })).toBeInTheDocument()
  })

  it('hides all write buttons for viewer', async () => {
    setRole('viewer')
    renderPage(<RepoScans />)
    await screen.findByText('api-repo')
    expect(screen.queryByRole('button', { name: /trigger api-repo/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /settings for api-repo/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /delete api-repo/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /add scan/i })).not.toBeInTheDocument()
  })
})

// ── SystemSettings ─────────────────────────────────────────────────────────────

describe('SystemSettings page — save button', () => {
  beforeEach(() => {
    vi.mocked(api.systemSettings.list).mockResolvedValue([])
  })

  it('shows Save for admin', async () => {
    setRole('admin')
    renderPage(<SystemSettings />)
    expect(await screen.findByRole('button', { name: /^save$/i })).toBeInTheDocument()
  })

  it('hides Save for operator', async () => {
    setRole('operator')
    renderPage(<SystemSettings />)
    await screen.findByText(/system settings/i)
    expect(screen.queryByRole('button', { name: /^save$/i })).not.toBeInTheDocument()
  })
})
