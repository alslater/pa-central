// Scans page
import React, { useEffect, useState } from 'react'
import { api, Scan, Host, RepoScanResultWithName } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Card, ScanBadge, RepoScanStatusBadge, ScanDetailTabs, Empty, timeAgo } from '@/components/ui'
import { useRovingTabs } from '@/lib/hooks'
import { ChevronDown, ChevronUp } from 'lucide-react'

type Tab = 'host' | 'repo'

// Data columns only; each table renders a trailing chevron/actions column
// separately with an sr-only label. The expanded findings row spans the full
// width, hence the +1 in the counts below.
const HOST_COLUMNS = ['Status', 'Project', 'Type', 'Findings', 'Risks', 'Host', 'Scanned'] as const
const REPO_COLUMNS = ['Status', 'Scan', 'Trigger', 'Findings', 'Risks', 'Breach', 'Scanned'] as const
const HOST_COLUMN_COUNT = HOST_COLUMNS.length + 1
const REPO_COLUMN_COUNT = REPO_COLUMNS.length + 1

export function Scans() {
  const [scans, setScans] = useState<Scan[]>([])
  const [hosts, setHosts] = useState<Record<number, Host>>({})
  const [repoResults, setRepoResults] = useState<RepoScanResultWithName[]>([])
  const [loading, setLoading] = useState(true)
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [expandedRepoId, setExpandedRepoId] = useState<number | null>(null)
  const [tab, setTab] = useState<Tab>('host')
  const TAB_IDS: readonly Tab[] = ['host', 'repo']
  const { tabRef, onKeyDown: onTabKeyDown } = useRovingTabs(TAB_IDS, tab, setTab)

  useEffect(() => {
    Promise.all([
      api.scans.list({}),
      api.hosts.list(),
      api.repoScans.allResults().catch(() => [] as typeof repoResults),
    ])
      .then(([s, h, rr]) => {
        setScans(s)
        setHosts(Object.fromEntries(h.map(host => [host.id, host])))
        setRepoResults(rr)
      })
      .finally(() => setLoading(false))
  }, [])

  const tabs: { id: Tab; label: string; count: number }[] = [
    { id: 'host', label: 'Host scans', count: scans.length },
    { id: 'repo', label: 'Repo scans', count: repoResults.length },
  ]

  return (
    <Shell>
      <PageHeader title="Scans" subtitle="Project scan results from across the fleet" />

      {/* Tab bar */}
      <div className="tab-bar" role="tablist">
        {tabs.map(t => (
          <button
            key={t.id}
            ref={tabRef(t.id)}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            aria-controls={`scans-panel-${t.id}`}
            id={`scans-tab-${t.id}`}
            tabIndex={tab === t.id ? 0 : -1}
            onClick={() => setTab(t.id)}
            onKeyDown={onTabKeyDown}
            className={tab === t.id ? 'tab-btn active' : 'tab-btn'}
          >
            {t.label}
            {!loading && (
              <span className={tab === t.id ? 'tab-count active' : 'tab-count'}>
                {t.count}
              </span>
            )}
          </button>
        ))}
      </div>

      <div className="page-content-flex">
        {loading ? <div className="loading-text">Loading…</div> : (
          <>
            <section
              id="scans-panel-host"
              role="tabpanel"
              aria-labelledby="scans-tab-host"
              hidden={tab !== 'host'}
            >
              {scans.length === 0 ? <Empty message="No host scan results yet." /> : (
                <Card>
                  <table className="data-table">
                    <thead>
                      <tr className="data-thead-tr">
                        {HOST_COLUMNS.map(h => (
                          <th key={h} scope="col" className="data-th">{h}</th>
                        ))}
                        <th scope="col" className="data-th"><span className="sr-only">Actions</span></th>
                      </tr>
                    </thead>
                    <tbody>
                      {scans.map(s => {
                        const hasFindings = s.findings && s.findings.length > 0
                        const hasRisks = s.risks && s.risks.length > 0
                        const hasDetail = hasFindings || hasRisks
                        const isExpanded = expandedId === s.id
                        return (
                          <React.Fragment key={s.id}>
                            <tr
                              className={`${isExpanded ? '' : 'data-tr'} ${hasDetail ? 'data-tr-clickable' : 'data-tr-static'}`}
                              onClick={hasDetail ? () => setExpandedId(isExpanded ? null : s.id) : undefined}
                              onKeyDown={hasDetail ? (e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setExpandedId(isExpanded ? null : s.id) } }) : undefined}
                              role={hasDetail ? 'button' : undefined}
                              tabIndex={hasDetail ? 0 : undefined}
                              aria-expanded={hasDetail ? isExpanded : undefined}
                            >
                              <td className="data-td"><ScanBadge status={s.status} /></td>
                              <td className="data-td">
                                <div className="project-path-cell">{s.project_path}</div>
                                {s.sources && s.sources.length > 0 && (
                                  <div className="sources-row">
                                    {s.sources.map(src => (
                                      <span key={src} className="source-tag">{src}</span>
                                    ))}
                                  </div>
                                )}
                              </td>
                              <td className="data-td-type">{s.scan_type}</td>
                              <td className={`data-td-count ${s.finding_count > 0 ? 'has-findings' : 'no-findings'}`}>{s.finding_count}</td>
                              <td className={`data-td-count ${hasRisks ? 'has-findings' : 'no-findings'}`}>
                                {s.risks == null
                                  ? <span title="No risk pass was reported for this scan — risk status is unknown, not clean">—</span>
                                  : s.risks.length}
                                {(s.risk_failures ?? 0) > 0 && (
                                  <span
                                    className="has-findings"
                                    title={`Risk scoring was unavailable for ${s.risk_failures} package(s) — an empty or short risk list may not mean the scan is clean`}
                                  > ⚠ {s.risk_failures} unscored</span>
                                )}
                              </td>
                              <td className="data-td-type">{hosts[s.host_id]?.name ?? `#${s.host_id}`}</td>
                              <td className="data-td-muted-11">{timeAgo(s.scanned_at)}</td>
                              <td className="data-td-chevron">
                                {hasDetail && (isExpanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}
                              </td>
                            </tr>
                            {isExpanded && hasDetail && (
                              <tr key={`${s.id}-detail`} className="data-tr">
                                <td colSpan={HOST_COLUMN_COUNT} className="findings-expanded-td">
                                  <ScanDetailTabs findings={s.findings} risks={s.risks} />
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        )
                      })}
                    </tbody>
                  </table>
                </Card>
              )}
            </section>

            <section
              id="scans-panel-repo"
              role="tabpanel"
              aria-labelledby="scans-tab-repo"
              hidden={tab !== 'repo'}
            >
              {repoResults.length === 0 ? <Empty message="No repo scan results yet." /> : (
                <Card>
                  <table className="data-table">
                    <thead>
                      <tr className="data-thead-tr">
                        {REPO_COLUMNS.map(h => (
                          <th key={h} scope="col" className="data-th">{h}</th>
                        ))}
                        <th scope="col" className="data-th"><span className="sr-only">Actions</span></th>
                      </tr>
                    </thead>
                    <tbody>
                      {repoResults.map(r => {
                        const hasFindings = r.findings && r.findings.length > 0
                        const hasRisks = r.risks && r.risks.length > 0
                        const hasDetail = hasFindings || hasRisks
                        const isExpanded = expandedRepoId === r.id
                        return (
                          <React.Fragment key={r.id}>
                            <tr
                              className={`${isExpanded ? '' : 'data-tr'} ${hasDetail ? 'data-tr-clickable' : 'data-tr-static'}`}
                              onClick={hasDetail ? () => setExpandedRepoId(isExpanded ? null : r.id) : undefined}
                              onKeyDown={hasDetail ? (e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setExpandedRepoId(isExpanded ? null : r.id) } }) : undefined}
                              role={hasDetail ? 'button' : undefined}
                              tabIndex={hasDetail ? 0 : undefined}
                              aria-expanded={hasDetail ? isExpanded : undefined}
                            >
                              <td className="data-td"><RepoScanStatusBadge status={r.status} /></td>
                              <td className="data-td">
                                <div className="scan-name-cell">{r.scan_name}</div>
                                <div className="scan-url-cell">{r.scan_url}</div>
                                {r.sources && r.sources.length > 0 && (
                                  <div className="sources-row">
                                    {r.sources.map(src => (
                                      <span key={src} className="source-tag">{src}</span>
                                    ))}
                                  </div>
                                )}
                              </td>
                              <td className="data-td-type">{r.triggered_by}</td>
                              <td className={`data-td-count ${(r.finding_count ?? 0) > 0 ? 'has-findings' : 'no-findings'}`}>{r.finding_count ?? 0}</td>
                              <td className={`data-td-count ${hasRisks ? 'has-findings' : 'no-findings'}`}>
                                {r.risks == null
                                  ? <span title="No risk pass was reported for this scan — risk status is unknown, not clean">—</span>
                                  : r.risks.length}
                                {(r.risk_failures ?? 0) > 0 && (
                                  <span
                                    className="has-findings"
                                    title={`Risk scoring was unavailable for ${r.risk_failures} package(s) — an empty or short risk list may not mean the scan is clean`}
                                  > ⚠ {r.risk_failures} unscored</span>
                                )}
                              </td>
                              <td className="data-td">
                                {r.scan_breach_count > 0 ? (
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[12px] font-semibold bg-status-fail/12 text-status-fail-text">
                                    {r.scan_breach_count}
                                  </span>
                                ) : (
                                  <span className="text-muted-foreground">—</span>
                                )}
                              </td>
                              <td className="data-td-muted-11">{r.started_at ? timeAgo(r.started_at) : '—'}</td>
                              <td className="data-td-chevron">
                                {hasDetail && (isExpanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}
                              </td>
                            </tr>
                            {isExpanded && hasDetail && (
                              <tr className="data-tr">
                                <td colSpan={REPO_COLUMN_COUNT} className="findings-expanded-td">
                                  <ScanDetailTabs findings={r.findings} risks={r.risks} />
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        )
                      })}
                    </tbody>
                  </table>
                </Card>
              )}
            </section>
          </>
        )}
      </div>
    </Shell>
  )
}
