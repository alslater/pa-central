import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router'
import { vi, beforeEach, describe, it, expect } from 'vitest'

// `pa scan-tools` scans (pa-central #26) on HostDetail: one card per pipx or uv tools directory,
// expanded into the tools it holds, each with only its own findings, risks and remediations
// (matched by `source`, e.g. "pipx:awscli").

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
  },
}))

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import HostDetail from '@/pages/HostDetail'

const PIPX = '/home/al/.local/share/pipx/venvs'

function tool(name: string, extra: Record<string, unknown> = {}) {
  return {
    manager: 'pipx', name, version: '1.0.0', python: '3.12', venv_root: `${PIPX}/${name}`,
    provenance: { kind: 'pypi', editable: false }, orphaned: [], unchecked: [], ...extra,
  }
}

function finding(pkg: string, source: string, advisory = `GHSA-${pkg}`) {
  return { package: pkg, ecosystem: 'PyPI', version: '1.26.0', advisory_id: advisory, severity: 'high', source }
}

function toolsScan(extra: Record<string, unknown> = {}) {
  return {
    id: 1, host_id: 1, project_path: PIPX, scan_type: 'tools',
    status: 'clean', finding_count: 0, findings: [], risks: [],
    risk_failures: 0, osv_failures: 0, sources: null, remediations: [],
    not_public: 0, yank_checked: false, yanked: null, yank_failures: null,
    manager: 'pipx', active: true, exists: true, run_id: 'r1', home: '/home/al',
    managers_scanned: ['pipx'], run_roots: [PIPX], tools: [], unchecked: [],
    scanned_at: '2026-10-30T00:00:00Z', received_at: '2026-10-30T00:00:00Z',
    ...extra,
  }
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
})

async function openScans(scans: Record<string, unknown>[]) {
  vi.mocked(api.hosts.latestScans).mockResolvedValue(scans as any)
  const user = userEvent.setup()
  render(
    <MemoryRouter initialEntries={['/hosts/1']}>
      <Routes><Route path="/hosts/:id" element={<HostDetail />} /></Routes>
    </MemoryRouter>,
  )
  await user.click(await screen.findByRole('tab', { name: /scans/i }))
  await screen.findAllByText(scans[0].project_path as string)
  return user
}

function cardOf(path: string): HTMLElement {
  return screen.getByText(path).closest('.host-scan-card-row') as HTMLElement
}

function toolGroup(name: string): HTMLElement {
  return screen.getByRole('group', { name: new RegExp(`^tool ${name.replace(/[()]/g, '\\$&')}`) })
}

describe('HostDetail — tools scans', () => {
  it('shows the manager and tool count, and expands into each tool with only its own findings', async () => {
    const user = await openScans([toolsScan({
      status: 'findings', finding_count: 2,
      tools: [tool('awscli'), tool('httpie', { version: '3.2.4' })],
      findings: [finding('urllib3', 'pipx:awscli'), finding('pygments', 'pipx:httpie')],
    })])
    const row = cardOf(PIPX)
    expect(within(row).getByText('pipx')).toBeInTheDocument()
    expect(within(row).getByText('2 tools')).toBeInTheDocument()

    await user.click(row)
    const aws = toolGroup('awscli')
    expect(within(aws).getByText('urllib3')).toBeInTheDocument()
    expect(within(aws).queryByText('pygments')).not.toBeInTheDocument()
    const httpie = toolGroup('httpie')
    expect(within(httpie).getByText('3.2.4')).toBeInTheDocument()
    expect(within(httpie).getByText('pygments')).toBeInTheDocument()
    expect(within(httpie).queryByText('urllib3')).not.toBeInTheDocument()
  })

  it('gives each tool its own remediation for a package two tools share', async () => {
    const rem = (source: string, to: string) => ({
      package: 'urllib3', ecosystem: 'PyPI', version: '1.26.0',
      advisories: [{ id: 'GHSA-urllib3', aliases: [] }], recommended_version: to,
      unfixed_advisory_ids: [], major_upgrade: false, verified: true,
      recommended_age_days: null, in_cooldown: null, source,
    })
    const user = await openScans([toolsScan({
      status: 'findings', finding_count: 2, tools: [tool('awscli'), tool('httpie')],
      findings: [finding('urllib3', 'pipx:awscli'), finding('urllib3', 'pipx:httpie')],
      remediations: [rem('pipx:awscli', '1.26.19'), rem('pipx:httpie', '2.2.2')],
    })])
    await user.click(cardOf(PIPX))
    expect(within(toolGroup('awscli')).getByText('→ 1.26.19')).toBeInTheDocument()
    expect(within(toolGroup('awscli')).queryByText('→ 2.2.2')).not.toBeInTheDocument()
    expect(within(toolGroup('httpie')).getByText('→ 2.2.2')).toBeInTheDocument()
  })

  it('keeps a finding whose source names no listed tool visible', async () => {
    const user = await openScans([toolsScan({
      status: 'findings', finding_count: 1, tools: [tool('awscli')],
      findings: [finding('orphanpkg', 'pipx:gone')],
    })])
    await user.click(cardOf(PIPX))
    expect(screen.getByText('orphanpkg')).toBeInTheDocument()
  })

  it('keeps each unmatched source\'s own remediation for a package they share', async () => {
    const rem = (source: string, to: string) => ({
      package: 'urllib3', ecosystem: 'PyPI', version: '1.26.0',
      advisories: [{ id: 'GHSA-urllib3', aliases: [] }], recommended_version: to,
      unfixed_advisory_ids: [], major_upgrade: false, verified: true,
      recommended_age_days: null, in_cooldown: null, source,
    })
    const user = await openScans([toolsScan({
      status: 'findings', finding_count: 2, tools: [],
      findings: [finding('urllib3', 'pipx:gone1'), finding('urllib3', 'pipx:gone2')],
      remediations: [rem('pipx:gone1', '1.26.19'), rem('pipx:gone2', '2.2.2')],
    })])
    await user.click(cardOf(PIPX))
    const gone1 = screen.getByRole('group', { name: 'other findings pipx:gone1' })
    const gone2 = screen.getByRole('group', { name: 'other findings pipx:gone2' })
    expect(within(gone1).getByText('→ 1.26.19')).toBeInTheDocument()
    expect(within(gone1).queryByText('→ 2.2.2')).not.toBeInTheDocument()
    expect(within(gone2).getByText('→ 2.2.2')).toBeInTheDocument()
  })

  it('lists yanked versions, even with no tools listed', async () => {
    const user = await openScans([toolsScan({
      tools: [], yank_checked: true, yank_failures: 0,
      yanked: [{ ecosystem: 'PyPI', package: 'requests', version: '2.32.0', reason: 'broken wheel' }],
    })])
    const row = cardOf(PIPX)
    expect(row).toHaveAttribute('role', 'button')
    await user.click(row)
    expect(screen.getByText('requests')).toBeInTheDocument()
    expect(screen.getByText('broken wheel')).toBeInTheDocument()
  })

  // `pa scan-tools --no-risk` sends risks: [] too, so an empty list cannot say the risk pass ran.
  it('says only that no findings or risks were reported when the risk list is empty', async () => {
    const user = await openScans([toolsScan({ risks: [], tools: [tool('awscli')] })])
    await user.click(cardOf(PIPX))
    expect(within(toolGroup('awscli')).getByText('No findings or risks reported.')).toBeInTheDocument()
  })

  it('says risks are unavailable, not that there are none, when no risk pass was reported', async () => {
    const user = await openScans([toolsScan({ risks: null, tools: [tool('awscli')] })])
    await user.click(cardOf(PIPX))
    const aws = toolGroup('awscli')
    expect(within(aws).getByText(/no findings\. risks unavailable/i)).toBeInTheDocument()
    expect(within(aws).queryByText(/no findings or risks/i)).not.toBeInTheDocument()
  })

  it('says a local checkout was not looked up, never that it is clean', async () => {
    const user = await openScans([toolsScan({
      not_public: 1,
      tools: [tool('pa', { provenance: { kind: 'local', editable: true, path: '/home/al/dev/package-alert' } })],
    })])
    await user.click(cardOf(PIPX))
    const pa = toolGroup('pa')
    expect(within(pa).getByText(/local checkout, not looked up/i)).toBeInTheDocument()
    expect(within(pa).getByText('editable')).toBeInTheDocument()
    expect(within(pa).getByText(/local checkout/i)).toHaveAttribute('title', expect.stringContaining('/home/al/dev/package-alert'))
  })

  it.each([
    [{ kind: 'index', editable: false, url: 'https://corp.example/simple' }, /private index/i],
    [{ kind: 'git', editable: false, url: 'git+https://github.com/o/r.git' }, /^git$/i],
    [{ kind: 'url', editable: false, url: 'https://x.example/t.whl' }, /^url$/i],
    [{ kind: 'unknown' }, /no install record/i],
    [{ kind: 'pypi', editable: false, extra_index: true }, /extra index/i],
    [{ kind: 'index', editable: false, index_source: 'config' }, /index from pip\/uv config/i],
  ])('labels provenance %o', async (provenance, label) => {
    const user = await openScans([toolsScan({ tools: [tool('t', { provenance })] })])
    await user.click(cardOf(PIPX))
    expect(within(toolGroup('t')).getByText(label)).toBeInTheDocument()
  })

  it('lists another interpreter\'s dirs as not scanned, never as safe to delete, and a tool\'s unchecked dirs as a warning', async () => {
    const user = await openScans([toolsScan({
      status: 'degraded', unchecked: [`${PIPX}/t/lib/python3.9`],
      tools: [tool('t', { orphaned: [`${PIPX}/t/lib/python3.11`], unchecked: [`${PIPX}/t/lib/python3.9`] })],
    })])
    await user.click(cardOf(PIPX))
    const t = toolGroup('t')
    expect(within(t).getByText(`${PIPX}/t/lib/python3.11`)).toBeInTheDocument()
    expect(within(t).getByText(/another interpreter's directory, not scanned/i)).toBeInTheDocument()
    expect(within(t).queryByText(/safe to delete/i)).not.toBeInTheDocument()
    expect(within(t).getByText(/not checked/i)).toBeInTheDocument()
  })

  it('shows unchecked directories from the list even when the status is findings', async () => {
    const user = await openScans([toolsScan({
      status: 'findings', finding_count: 1, tools: [tool('awscli')],
      findings: [finding('urllib3', 'pipx:awscli')], unchecked: [`${PIPX}/locked`],
    })])
    const row = cardOf(PIPX)
    expect(within(row).getByText('⚠ 1 not checked')).toBeInTheDocument()
    await user.click(row)
    expect(screen.getByText(`${PIPX}/locked`)).toBeInTheDocument()
  })

  it('expands to the unchecked list when an unreadable venv is the only thing in the directory', async () => {
    const user = await openScans([toolsScan({ status: 'degraded', tools: [], unchecked: [`${PIPX}/locked`] })])
    const row = cardOf(PIPX)
    expect(row).toHaveAttribute('role', 'button')
    await user.click(row)
    expect(screen.getByText(`${PIPX}/locked`)).toBeInTheDocument()
  })

  // package-alert calls a leftover layout deletable only after checks the payload does not carry.
  it('labels a leftover layout as unused by pipx, never as safe to delete, and keeps its findings visible', async () => {
    const user = await openScans([toolsScan({
      active: false, status: 'findings', finding_count: 1, tools: [tool('awscli')],
      findings: [finding('urllib3', 'pipx:awscli')],
    })])
    const row = cardOf(PIPX)
    const chip = within(row).getByText(/leftover layout, pipx no longer uses it/i)
    expect(chip).not.toHaveAttribute('title', expect.stringMatching(/delet/i))
    expect(within(row).queryByText(/safe to delete/i)).not.toBeInTheDocument()
    await user.click(row)
    expect(screen.getByText('urllib3')).toBeInTheDocument()
  })

  it('shows a manager with no directory as having no tools, not as orphaned, and not expandable', async () => {
    await openScans([toolsScan({ exists: false, tools: [] })])
    const row = cardOf(PIPX)
    expect(within(row).getByText(/no pipx tools/i)).toBeInTheDocument()
    expect(within(row).queryByText(/leftover/i)).not.toBeInTheDocument()
    expect(row).not.toHaveAttribute('role')
  })

  it('shows pipx\'s shared libraries as a tool', async () => {
    const user = await openScans([toolsScan({ tools: [tool('(shared)', { provenance: { kind: 'unknown' } })] })])
    await user.click(cardOf(PIPX))
    expect(toolGroup('(shared)')).toBeInTheDocument()
  })

  it('renders a project and an installed scan of the same path as two cards', async () => {
    const base = {
      host_id: 1, project_path: '/app', status: 'clean', finding_count: 0, findings: null, risks: [],
      risk_failures: 0, osv_failures: 0, sources: null, remediations: null,
      not_public: 0, yank_checked: false, yanked: null, yank_failures: null,
      scanned_at: '2026-10-30T00:00:00Z', received_at: '2026-10-30T00:00:00Z',
    }
    const user = await openScans([
      { ...base, id: 1, scan_type: 'project', findings: [{ package: 'flask' }] },
      { ...base, id: 2, scan_type: 'installed', findings: [{ package: 'django' }] },
    ])
    const [project, installed] = screen.getAllByText('/app').map(el => el.closest('.host-scan-card-row') as HTMLElement)
    expect(within(project).getByText('project')).toBeInTheDocument()
    expect(within(installed).getByText('installed')).toBeInTheDocument()
    await user.click(project)   // expands that card only
    expect(screen.getByText('flask')).toBeInTheDocument()
    expect(screen.queryByText('django')).not.toBeInTheDocument()
  })
})
