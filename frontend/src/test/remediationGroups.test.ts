import { describe, it, expect } from 'vitest'
import { groupFindings, severityRank, type RawFinding } from '@/lib/remediationGroups'
import type { Remediation } from '@/lib/api'

const f = (advisory_id: string, extra: Partial<RawFinding> = {}): RawFinding => ({
  package: 'django', ecosystem: 'PyPI', version: '5.2.15', advisory_id, severity: 'medium', ...extra,
})

const rem = (extra: Partial<Remediation> = {}): Remediation => ({
  package: 'django', ecosystem: 'PyPI', version: '5.2.15',
  advisories: [], recommended_version: '5.2.17', unfixed_advisory_ids: [],
  major_upgrade: false, verified: true, recommended_age_days: null, in_cooldown: null,
  ...extra,
})

describe('groupFindings', () => {
  it('groups by (ecosystem, package, version) and attaches the matching remediation', () => {
    const r = rem({ advisories: [{ id: 'GHSA-a', aliases: [] }] })
    const groups = groupFindings([f('GHSA-a'), f('GHSA-x', { package: 'flask' })], [r])
    expect(groups).toHaveLength(2)
    const django = groups.find(g => g.package === 'django')!
    expect(django.remediation).toBe(r)
    expect(groups.find(g => g.package === 'flask')!.remediation).toBeNull()
  })

  it('folds alias twins into one row, represented by the primary id', () => {
    const groups = groupFindings(
      [f('PYSEC-1'), f('GHSA-a')],
      [rem({ advisories: [{ id: 'GHSA-a', aliases: ['PYSEC-1'] }] })],
    )
    expect(groups[0].rows).toHaveLength(1)
    expect(groups[0].rows[0].finding.advisory_id).toBe('GHSA-a')
    expect(groups[0].rows[0].aliases).toEqual(['PYSEC-1'])
  })

  it('takes the most severe rating and any malicious flag across merged aliases, as package-alert does', () => {
    const groups = groupFindings(
      [f('GHSA-a', { severity: 'MEDIUM' }), f('PYSEC-1', { severity: 'CRITICAL', is_malicious: true })],
      [rem({ advisories: [{ id: 'GHSA-a', aliases: ['PYSEC-1'] }] })],
    )
    const row = groups[0].rows[0]
    expect(row.finding.advisory_id).toBe('GHSA-a')
    expect(row.finding.severity).toBe('CRITICAL')
    expect(row.finding.is_malicious).toBe(true)
  })

  it('keeps the primary rating when it is already the most severe', () => {
    const groups = groupFindings(
      [f('GHSA-a', { severity: 'HIGH' }), f('PYSEC-1', { severity: undefined })],
      [rem({ advisories: [{ id: 'GHSA-a', aliases: ['PYSEC-1'] }] })],
    )
    expect(groups[0].rows[0].finding.severity).toBe('HIGH')
    expect(groups[0].rows[0].finding.is_malicious).toBeUndefined()
  })

  it('falls back to a merged alias summary when the representative has none', () => {
    const groups = groupFindings(
      [f('PYSEC-1', { summary: undefined }), f('GHSA-b', { summary: 'Heap overflow' })],
      [rem({ advisories: [{ id: 'GHSA-a', aliases: ['PYSEC-1', 'GHSA-b'] }] })],
    )
    expect(groups[0].rows[0].finding.advisory_id).toBe('PYSEC-1')
    expect(groups[0].rows[0].finding.summary).toBe('Heap overflow')
  })

  it('ranks moderate as medium, the way it is displayed', () => {
    expect(severityRank('moderate')).toBe(severityRank('medium'))
    expect(severityRank('MODERATE')).toBe(severityRank('MEDIUM'))
    const groups = groupFindings([f('GHSA-low', { severity: 'LOW' }), f('GHSA-mod', { severity: 'MODERATE' })], [])
    expect(groups[0].worstSeverity).toBe('moderate')
    expect(groups[0].rows.map(r => r.finding.advisory_id)).toEqual(['GHSA-mod', 'GHSA-low'])
  })

  it('merges a moderate alias over a low primary', () => {
    const groups = groupFindings(
      [f('GHSA-a', { severity: 'LOW' }), f('PYSEC-1', { severity: 'MODERATE' })],
      [rem({ advisories: [{ id: 'GHSA-a', aliases: ['PYSEC-1'] }] })],
    )
    expect(groups[0].rows[0].finding.severity).toBe('MODERATE')
  })

  it('does not mutate the input findings when merging', () => {
    const primary = f('GHSA-a', { severity: 'LOW' })
    groupFindings([primary, f('PYSEC-1', { severity: 'HIGH' })], [rem({ advisories: [{ id: 'GHSA-a', aliases: ['PYSEC-1'] }] })])
    expect(primary.severity).toBe('LOW')
  })

  it('uses the alias finding when the primary finding is absent', () => {
    const groups = groupFindings([f('PYSEC-1')], [rem({ advisories: [{ id: 'GHSA-a', aliases: ['PYSEC-1'] }] })])
    expect(groups[0].rows).toHaveLength(1)
    expect(groups[0].rows[0].finding.advisory_id).toBe('PYSEC-1')
    expect(groups[0].rows[0].aliases).toEqual([])
  })

  it('orders rows by the remediation advisories, then uncovered findings by severity', () => {
    const groups = groupFindings(
      [f('GHSA-low', { severity: 'low' }), f('GHSA-extra', { severity: 'critical' }), f('GHSA-hi', { severity: 'high' }), f('GHSA-low2', { severity: 'low' })],
      [rem({ advisories: [{ id: 'GHSA-low', aliases: [] }, { id: 'GHSA-hi', aliases: [] }] })],
    )
    expect(groups[0].rows.map(r => r.finding.advisory_id)).toEqual(['GHSA-low', 'GHSA-hi', 'GHSA-extra', 'GHSA-low2'])
  })

  it('never marks a row unfixed when recommended_version is null', () => {
    const groups = groupFindings(
      [f('GHSA-a')],
      [rem({ recommended_version: null, advisories: [{ id: 'GHSA-a', aliases: [] }], unfixed_advisory_ids: ['GHSA-a'] })],
    )
    expect(groups[0].rows.map(r => r.unfixed)).toEqual([false])
  })

  it('marks rows whose id or alias is in unfixed_advisory_ids', () => {
    const groups = groupFindings(
      [f('GHSA-a'), f('GHSA-b')],
      [rem({ advisories: [{ id: 'GHSA-a', aliases: [] }, { id: 'GHSA-b', aliases: [] }], unfixed_advisory_ids: ['GHSA-b'] })],
    )
    expect(groups[0].rows.map(r => r.unfixed)).toEqual([false, true])
  })

  it('matches a null finding version to a null remediation version', () => {
    const groups = groupFindings([f('GHSA-a', { version: undefined })], [rem({ version: null, advisories: [{ id: 'GHSA-a', aliases: [] }] })])
    expect(groups[0].remediation).not.toBeNull()
    expect(groups[0].version).toBeNull()
  })

  it('keeps findings with no matching remediation visible', () => {
    const groups = groupFindings([f('GHSA-a', { version: '9.9.9' })], [rem({ advisories: [{ id: 'GHSA-a', aliases: [] }] })])
    expect(groups).toHaveLength(1)
    expect(groups[0].remediation).toBeNull()
    expect(groups[0].rows).toHaveLength(1)
  })

  it('gives duplicate findings unique row keys', () => {
    const groups = groupFindings([f('GHSA-a'), f('GHSA-a')], [])
    const keys = groups.flatMap(g => g.rows.map(r => r.key))
    expect(new Set(keys).size).toBe(keys.length)
  })

  it('folds exact duplicates of an advisory into one row with no self-alias', () => {
    const groups = groupFindings([f('GHSA-a'), f('GHSA-a')], [rem({ advisories: [{ id: 'GHSA-a', aliases: [] }] })])
    expect(groups[0].rows).toHaveLength(1)
    expect(groups[0].rows[0].aliases).toEqual([])
  })

  it('orders groups malicious first, then by worst severity, else first appearance', () => {
    const groups = groupFindings([
      f('A', { package: 'low-a', severity: 'low' }),
      f('B', { package: 'crit', severity: 'critical' }),
      f('C', { package: 'low-b', severity: 'low' }),
      f('D', { package: 'mal', severity: 'low', is_malicious: true }),
    ], [])
    expect(groups.map(g => g.package)).toEqual(['mal', 'crit', 'low-a', 'low-b'])
    expect(groups[1].worstSeverity).toBe('critical')
  })
})
