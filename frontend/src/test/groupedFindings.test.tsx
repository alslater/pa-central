import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FindingsTable } from '@/components/ui'
import type { Remediation } from '@/lib/api'

const finding = (advisory_id: string, extra: Record<string, unknown> = {}) => ({
  package: 'django', ecosystem: 'PyPI', version: '5.2.15', advisory_id,
  severity: 'high', summary: `summary ${advisory_id}`, fixed_versions: ['5.2.17'], ...extra,
})

const rem = (extra: Partial<Remediation> = {}): Remediation => ({
  package: 'django', ecosystem: 'PyPI', version: '5.2.15',
  advisories: [{ id: 'GHSA-a', aliases: ['PYSEC-1'] }],
  recommended_version: '5.2.17', unfixed_advisory_ids: [],
  major_upgrade: null, verified: null, recommended_age_days: null, in_cooldown: null,
  ...extra,
})

describe('FindingsTable grouped by remediation', () => {
  it('renders a package header with the recommended version', () => {
    render(<FindingsTable findings={[finding('GHSA-a')]} remediations={[rem()]} />)
    const group = screen.getByRole('group', { name: /django 5\.2\.15/ })
    expect(within(group).getByText('→ 5.2.17')).toBeInTheDocument()
  })

  it('case (a): no recommendation lists the sorted, de-duplicated union of fixed versions', () => {
    render(<FindingsTable
      findings={[
        finding('GHSA-a', { fixed_versions: ['5.2.17', '4.2.9'] }),
        finding('GHSA-b', { fixed_versions: '5.2.17, 3.0.1' }),
      ]}
      remediations={[rem({ recommended_version: null, unfixed_advisory_ids: null })]}
    />)
    expect(screen.getByText('Fixed in: 3.0.1, 4.2.9, 5.2.17')).toBeInTheDocument()
    expect(screen.queryByText('No fixed version known')).not.toBeInTheDocument()
  })

  it('case (a): no recommendation and no fixed versions shows "No fixed version known"', () => {
    render(<FindingsTable
      findings={[finding('GHSA-a', { fixed_versions: [] })]}
      remediations={[rem({ recommended_version: null, unfixed_advisory_ids: null })]}
    />)
    expect(screen.getByText('No fixed version known')).toBeInTheDocument()
    expect(screen.queryByText(/Fixed in:/)).not.toBeInTheDocument()
  })

  it('case (b): a recommendation with no fixed version says so, with no "Leaves N open" and no unfixed note', async () => {
    const user = userEvent.setup()
    render(<FindingsTable
      findings={[finding('GHSA-a')]}
      remediations={[rem({ recommended_version: null, unfixed_advisory_ids: ['GHSA-a'] })]}
    />)
    expect(screen.getByText('No fixed version known')).toBeInTheDocument()
    expect(screen.queryByText(/Fixed in:/)).not.toBeInTheDocument()
    expect(screen.queryByText(/Leaves \d+ open/)).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /GHSA-a — view details/ }))
    expect(screen.queryByText('Not fixed by recommended version')).not.toBeInTheDocument()
  })

  it('shows each tag only for a true / non-empty field, never for null', () => {
    const { rerender } = render(<FindingsTable findings={[finding('GHSA-a')]} remediations={[rem()]} />)
    for (const label of [/Major upgrade/, /Unverified/, /In cooldown/, /Leaves \d+ open/]) {
      expect(screen.queryByText(label)).not.toBeInTheDocument()
    }
    rerender(<FindingsTable findings={[finding('GHSA-a')]} remediations={[rem({
      major_upgrade: true, verified: false, in_cooldown: true, recommended_age_days: 3.9,
      unfixed_advisory_ids: ['GHSA-a'],
    })]} />)
    expect(screen.getByText('Major upgrade')).toBeInTheDocument()
    expect(screen.getByText('Unverified')).toBeInTheDocument()
    expect(screen.getByText('In cooldown · 3d')).toBeInTheDocument()
    expect(screen.getByText('Leaves 1 open')).toBeInTheDocument()
  })

  it('does not show tags for explicit false values', () => {
    render(<FindingsTable findings={[finding('GHSA-a')]} remediations={[rem({ major_upgrade: false, verified: true, in_cooldown: false })]} />)
    expect(screen.queryByText('Major upgrade')).not.toBeInTheDocument()
    expect(screen.queryByText('Unverified')).not.toBeInTheDocument()
    expect(screen.queryByText(/In cooldown/)).not.toBeInTheDocument()
  })

  it('merges alias twins into one row listing the alias', () => {
    render(<FindingsTable findings={[finding('GHSA-a'), finding('PYSEC-1')]} remediations={[rem()]} />)
    expect(screen.getAllByRole('button', { name: /view details/ })).toHaveLength(1)
    expect(screen.getByText('GHSA-a + PYSEC-1')).toBeInTheDocument()
  })

  it('gives a package with moderate and low findings a medium badge', () => {
    render(<FindingsTable
      findings={[finding('GHSA-a', { severity: 'low' }), finding('GHSA-m', { severity: 'moderate' })]}
      remediations={[rem({ advisories: [] })]}
    />)
    const header = screen.getByRole('group', { name: /django 5\.2\.15/ }).firstElementChild as HTMLElement
    expect(within(header).getByText(/^medium$/i)).toBeInTheDocument()
    expect(within(header).queryByText(/^low$/i)).not.toBeInTheDocument()
  })

  it('shows the merged row and drawer as malicious when only an alias is flagged', async () => {
    const user = userEvent.setup()
    render(<FindingsTable
      findings={[finding('GHSA-a', { severity: 'medium' }), finding('PYSEC-1', { severity: 'critical', is_malicious: true })]}
      remediations={[rem()]}
    />)
    const row = screen.getByRole('button', { name: /GHSA-a — view details/ })
    expect(within(row).getByText(/MALICIOUS/)).toBeInTheDocument()
    expect(within(row).getByText(/critical/i)).toBeInTheDocument()
    await user.click(row)
    expect(screen.getByText('⚠ Malicious')).toBeInTheDocument()
  })

  it('still renders a package that has no matching remediation', () => {
    render(<FindingsTable
      findings={[finding('GHSA-a'), finding('GHSA-f', { package: 'flask', version: '1.0' })]}
      remediations={[rem()]}
    />)
    expect(screen.getByRole('group', { name: /flask 1\.0/ })).toBeInTheDocument()
    expect(screen.getByText('summary GHSA-f')).toBeInTheDocument()
  })

  it('drawer shows aliases and the unfixed note', async () => {
    const user = userEvent.setup()
    render(<FindingsTable
      findings={[finding('GHSA-a'), finding('PYSEC-1')]}
      remediations={[rem({ unfixed_advisory_ids: ['GHSA-a'] })]}
    />)
    await user.click(screen.getByRole('button', { name: /GHSA-a — view details/ }))
    expect(screen.getByText('Also reported as')).toBeInTheDocument()
    expect(screen.getByText('PYSEC-1')).toBeInTheDocument()
    expect(screen.getByText('Not fixed by recommended version')).toBeInTheDocument()
  })

  it('pages by package group, never splitting a package', async () => {
    const user = userEvent.setup()
    // 26 packages; the last one has 3 advisories.
    const findings = Array.from({ length: 25 }, (_, i) => finding(`GHSA-${i}`, { package: `pkg-${String(i).padStart(2, '0')}`, severity: 'critical' }))
    findings.push(...['X1', 'X2', 'X3'].map(id => finding(id, { package: 'zz-last', severity: 'low' })))
    render(<FindingsTable findings={findings} remediations={[rem()]} />)
    expect(screen.getByText('1–25 of 26 packages')).toBeInTheDocument()
    expect(screen.queryByText('summary X1')).not.toBeInTheDocument()
    await user.click(screen.getByText('→'))
    expect(screen.getByText('26–26 of 26 packages')).toBeInTheDocument()
    expect(screen.getByText('summary X1')).toBeInTheDocument()
    expect(screen.getByText('summary X3')).toBeInTheDocument()
  })

  it('counts pages in packages, not advisory rows', () => {
    // 25 packages x 2 advisories = 50 rows but only 25 groups: one page, no pager.
    const findings = Array.from({ length: 25 }, (_, i) => [`A${i}`, `B${i}`].map(id =>
      finding(id, { package: `pkg-${String(i).padStart(2, '0')}` }))).flat()
    render(<FindingsTable findings={findings} remediations={[rem()]} />)
    expect(screen.queryByText(/of \d+ packages/)).not.toBeInTheDocument()
    expect(screen.getByText('summary B24')).toBeInTheDocument()
  })

  it('falls back to the flat table when remediations is null or empty', () => {
    const { rerender } = render(<FindingsTable findings={[finding('GHSA-a')]} remediations={null} />)
    expect(screen.queryByRole('group')).not.toBeInTheDocument()
    rerender(<FindingsTable findings={[finding('GHSA-a')]} remediations={[]} />)
    expect(screen.queryByRole('group')).not.toBeInTheDocument()
  })

  it('survives remediations switching between present and absent across renders', () => {
    const { rerender } = render(<FindingsTable findings={[finding('GHSA-a')]} remediations={[rem()]} />)
    rerender(<FindingsTable findings={[finding('GHSA-a')]} remediations={null} />)
    rerender(<FindingsTable findings={[finding('GHSA-a')]} remediations={[rem()]} />)
    expect(screen.getByText('→ 5.2.17')).toBeInTheDocument()
  })
})
