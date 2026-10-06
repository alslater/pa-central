import type { Remediation } from '@/lib/api'

// Grouping for the raw-scan FindingsTable when package-alert (>= 0.9.0)
// supplied `remediations`. This follows package-alert's own grouping key and
// alias merge (remediation.advisories) and never computes either itself, so
// the view cannot drift from the advice the scan produced.

export interface RawFinding {
  package?: string
  ecosystem?: string
  version?: string
  advisory_id?: string
  severity?: string
  summary?: string
  details?: string
  fixed_versions?: string | string[] | null
  url?: string
  is_malicious?: boolean
  [key: string]: unknown
}

export const SEV_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, warning: 3, low: 4, info: 5,
}

// GHSA's "moderate" is ranked as the "medium" it is displayed as (see
// toSeverity in ui.tsx); left unranked it sorted below "low".
export function severityRank(sev: string | undefined): number {
  const s = sev?.toLowerCase() ?? 'info'
  return SEV_ORDER[s === 'moderate' ? 'medium' : s] ?? 9
}

export interface AdvisoryRow {
  key: string
  finding: RawFinding
  /** Other ids folded into this row (the same flaw under another database's id). */
  aliases: string[]
  /** The recommended version leaves this advisory open. */
  unfixed: boolean
}

export interface PackageGroup {
  key: string
  package: string
  ecosystem: string
  version: string | null
  /** null when the scan gave no remediation for this exact (ecosystem, package, version). */
  remediation: Remediation | null
  rows: AdvisoryRow[]
  /** Every finding in the group, including alias twins folded into a row. */
  findings: RawFinding[]
  worstSeverity: string
  malicious: boolean
}

const str = (v: unknown): string | null => (typeof v === 'string' ? v : null)

// Same key package-alert groups by. JSON.stringify so a delimiter inside a
// value can't collide two keys; a missing version is null on both sides.
function packageKey(ecosystem: unknown, pkg: unknown, version: unknown): string {
  return JSON.stringify([str(ecosystem) ?? '', str(pkg) ?? '', str(version)])
}

// One flaw reported under several ids: the representative finding with the
// fields package-alert's Advisory aggregates across members (severity: most
// severe; is_malicious: any; summary: first one present), so a row never
// understates what an alias reported. A new object; inputs are not mutated.
function mergeAliases(rep: RawFinding, members: RawFinding[]): RawFinding {
  const worst = [...members].sort((a, b) => severityRank(a.severity) - severityRank(b.severity))[0]
  const merged: RawFinding = { ...rep, severity: worst.severity ?? rep.severity }
  if (members.some(m => m.is_malicious === true)) merged.is_malicious = true
  if (!rep.summary) merged.summary = members.find(m => m.summary)?.summary ?? rep.summary
  return merged
}

// A null recommended_version means there is no version for an advisory to be
// "not fixed by", so nothing is unfixed (package-alert's renderer does the same).
function buildRows(groupKey: string, members: RawFinding[], remediation: Remediation | null): AdvisoryRow[] {
  const used = new Set<RawFinding>()
  const unfixedIds = new Set(remediation?.recommended_version ? remediation.unfixed_advisory_ids ?? [] : [])
  const rows: Omit<AdvisoryRow, 'key'>[] = []

  for (const entry of remediation?.advisories ?? []) {
    const ids = new Set([entry.id, ...entry.aliases].filter((x): x is string => typeof x === 'string' && x !== ''))
    const matched = members.filter(m => !used.has(m) && typeof m.advisory_id === 'string' && ids.has(m.advisory_id))
    if (!matched.length) continue
    matched.forEach(m => used.add(m))
    // The primary id represents the row; if this scan only reported an
    // alias, that alias finding stands in for it.
    const rep = matched.find(m => m.advisory_id === entry.id) ?? matched[0]
    const aliases = [...new Set(matched.map(m => m.advisory_id as string))].filter(id => id !== rep.advisory_id)
    rows.push({ finding: mergeAliases(rep, matched), aliases, unfixed: [...ids].some(id => unfixedIds.has(id)) })
  }

  // Anything the remediation doesn't cover still shows, never hidden.
  const rest = members.filter(m => !used.has(m)).sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
  for (const m of rest) rows.push({ finding: m, aliases: [], unfixed: false })

  const counts = new Map<string, number>()
  return rows.map(r => {
    const base = JSON.stringify([groupKey, r.finding.advisory_id ?? ''])
    const n = (counts.get(base) ?? 0) + 1
    counts.set(base, n)
    return { ...r, key: n > 1 ? `${base}:${n}` : base }
  })
}

export function groupFindings(findings: RawFinding[], remediations: Remediation[]): PackageGroup[] {
  const remByKey = new Map<string, Remediation>()
  for (const r of remediations) {
    const k = packageKey(r.ecosystem, r.package, r.version)
    if (!remByKey.has(k)) remByKey.set(k, r)
  }

  const membersByKey = new Map<string, RawFinding[]>()
  for (const f of findings) {
    const k = packageKey(f.ecosystem, f.package, f.version)
    const list = membersByKey.get(k)
    if (list) list.push(f)
    else membersByKey.set(k, [f])
  }

  const groups: PackageGroup[] = []
  for (const [key, members] of membersByKey) {
    const first = members[0]
    const remediation = remByKey.get(key) ?? null
    const worst = [...members].sort((a, b) => severityRank(a.severity) - severityRank(b.severity))[0]
    groups.push({
      key,
      package: str(first.package) ?? '',
      ecosystem: str(first.ecosystem) ?? '',
      version: str(first.version),
      remediation,
      rows: buildRows(key, members, remediation),
      findings: members,
      worstSeverity: worst.severity?.toLowerCase() ?? 'info',
      malicious: members.some(m => m.is_malicious === true),
    })
  }

  // Array.prototype.sort is stable, so ties keep first-appearance order.
  return groups.sort((a, b) =>
    Number(b.malicious) - Number(a.malicious) || severityRank(a.worstSeverity) - severityRank(b.worstSeverity))
}
