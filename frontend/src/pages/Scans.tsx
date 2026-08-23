// Scans page — one row per repo scan project, expand for Findings/Risks
import { useCallback, useEffect, useRef, useState } from 'react'
import { api, RepoScanHeadline, FindingRecord, RiskRecord, ExposureHistory } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Card, RepoScanStatusBadge, SeverityBadge, RiskLevelBadge, RecordTabs, Empty, Input, timeAgo, useToast } from '@/components/ui'
import { ExposureChart } from '@/components/ExposureChart'
import { useAuth } from '@/hooks/useAuth'
import { ChevronDown, ChevronUp } from 'lucide-react'

const SEVERITIES = ['critical', 'high', 'medium', 'warning', 'low', 'info'] as const
const RISK_LEVELS = ['critical', 'warning', 'info'] as const

function ProjectRow({ headline, isExpanded, onToggle, show, onChanged }: {
  headline: RepoScanHeadline
  isExpanded: boolean
  onToggle: () => void
  show: (msg: string, kind: 'ok' | 'err') => void
  onChanged: () => void
}) {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [findings, setFindings] = useState<FindingRecord[] | null>(null)
  const [risks, setRisks] = useState<RiskRecord[] | null>(null)
  const [exposureHistory, setExposureHistory] = useState<ExposureHistory | null>(null)
  const [loading, setLoading] = useState(false)
  const [detailError, setDetailError] = useState(false)
  // Guards against overlapping loadDetail calls (e.g. rapid accept/revoke,
  // each triggering a background refresh) — only the most recently started
  // request may commit state, so a slower older response can't overwrite
  // a faster newer one on resolution.
  const requestSeq = useRef(0)

  const loadDetail = useCallback((background = false) => {
    const seq = ++requestSeq.current
    setDetailError(false)
    if (!background) setLoading(true)
    Promise.all([
      api.findings.listAllForRepo(headline.id),
      api.risks.listAllForRepo(headline.id),
      isAdmin ? api.repoScans.exposureHistory(headline.id).catch(() => null) : Promise.resolve(null),
    ])
      .then(([f, r, eh]) => {
        if (seq !== requestSeq.current) return
        setFindings(f); setRisks(r); setExposureHistory(eh)
      })
      .catch((e: Error) => {
        if (seq !== requestSeq.current) return
        if (!background) setDetailError(true)
        show(e.message ?? 'Failed to load details', 'err')
      })
      .finally(() => {
        if (seq !== requestSeq.current) return
        setLoading(false)
      })
  }, [headline.id, isAdmin, show])

  useEffect(() => { if (isExpanded && findings === null) loadDetail() }, [isExpanded, findings, loadDetail]) // eslint-disable-line react-hooks/set-state-in-effect -- loads detail on first expand; matches FindingsPanel/RisksPanel in RepoScans.tsx

  return (
    <Card className="card-mb-12">
      <div
        className="scan-card-header data-tr-clickable"
        onClick={onToggle}
        onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onToggle() } }}
        role="button"
        tabIndex={0}
        aria-expanded={isExpanded}
      >
        {headline.latest_status && <RepoScanStatusBadge status={headline.latest_status} />}
        <div className="scan-card-info">
          <div className="scan-card-name-row">{headline.name}</div>
          <div className="scan-card-meta">{headline.url}</div>
        </div>
        <div className="flex gap-1.5 items-center">
          {SEVERITIES.filter(s => headline.open_findings_by_severity[s] > 0).map(s => (
            <span key={s} className="flex items-center gap-1">
              <SeverityBadge severity={s} />
              <span className="text-[11px] font-semibold">{headline.open_findings_by_severity[s]}</span>
            </span>
          ))}
          {RISK_LEVELS.filter(l => headline.open_risks_by_level[l] > 0).map(l => (
            <span key={l} className="flex items-center gap-1">
              <RiskLevelBadge level={l} />
              <span className="text-[11px] font-semibold">{headline.open_risks_by_level[l]}</span>
            </span>
          ))}
          {headline.breach && (
            <span className="text-[11px] font-semibold px-1.5 py-0.5 rounded bg-status-fail/12 text-status-fail-text">
              SLA breach ×{headline.breach_count}
            </span>
          )}
        </div>
        {headline.latest_scanned_at && (
          <span className="scan-card-last-scan">{timeAgo(headline.latest_scanned_at)}</span>
        )}
        <span className="result-chevron">
          {isExpanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        </span>
      </div>
      {isExpanded && (
        <div className="form-section-border">
          {detailError ? (
            <div className="p-3 text-[13px] text-status-fail-text flex items-center gap-2">
              Failed to load details.
              <button type="button" onClick={() => loadDetail()} className="underline hover:no-underline">Retry</button>
            </div>
          ) : loading || findings === null || risks === null ? (
            <div className="p-3 text-[13px] text-muted-foreground">Loading…</div>
          ) : (
            <>
              {exposureHistory && exposureHistory.points.length > 0 && (
                <ExposureChart
                  points={exposureHistory.points}
                  title={`Exposure over time for ${headline.name}`}
                  desc="Weighted severity of open, unaccepted findings for this repo scan, by day."
                />
              )}
              <RecordTabs findings={findings} risks={risks} show={show} onChanged={() => { loadDetail(true); onChanged() }} />
            </>
          )}
        </div>
      )}
    </Card>
  )
}

export function Scans() {
  const [headlines, setHeadlines] = useState<RepoScanHeadline[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [filter, setFilter] = useState('')
  const { show, Toast } = useToast()
  // Guards against overlapping load() calls (e.g. two quick accept/revoke
  // actions on different rows, each triggering a background headlines
  // refresh) — only the most recently started request may commit state, and
  // a response for a request no longer current (including one still
  // in-flight when the component unmounts) is ignored.
  const requestSeq = useRef(0)

  const load = useCallback((background = false) => {
    const seq = ++requestSeq.current
    if (!background) { setLoading(true); setLoadError(false) }
    api.repoScans.headlines().then(headlines => {
      if (seq !== requestSeq.current) return
      setHeadlines(headlines)
    }).catch((e: Error) => {
      if (seq !== requestSeq.current) return
      if (!background) setLoadError(true)
      show(e.message ?? 'Failed to load scans', 'err')
    }).finally(() => {
      if (seq !== requestSeq.current) return
      if (!background) setLoading(false)
    })
  }, [show])
  useEffect(() => {
    load()
    return () => { requestSeq.current += 1 }
  }, [load]) // eslint-disable-line react-hooks/set-state-in-effect -- initial load on mount; matches FindingsPanel/RisksPanel in RepoScans.tsx

  const loadHeadlinesBackground = useCallback(() => { load(true) }, [load])

  const filtered = headlines.filter(h => h.name.toLowerCase().includes(filter.trim().toLowerCase()))

  return (
    <Shell>
      <PageHeader
        title="Scans"
        subtitle="Repo scan results — current findings and risks by project"
        action={
          <Input
            type="search"
            placeholder="Filter projects…"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            aria-label="Filter projects"
            className="w-64"
          />
        }
      />
      <div className="page-content-flex">
        {loading ? (
          <div className="loading-text">Loading…</div>
        ) : loadError ? (
          <div className="p-3 text-[13px] text-status-fail-text flex items-center gap-2">
            Failed to load scans.
            <button type="button" onClick={() => load()} className="underline hover:no-underline">Retry</button>
          </div>
        ) : headlines.length === 0 ? (
          <Empty message="No repo scans configured." />
        ) : filtered.length === 0 ? (
          <Empty message="No projects match this filter." />
        ) : (
          filtered.map(h => (
            <ProjectRow
              key={h.id}
              headline={h}
              isExpanded={expandedId === h.id}
              onToggle={() => setExpandedId(expandedId === h.id ? null : h.id)}
              show={show}
              onChanged={loadHeadlinesBackground}
            />
          ))
        )}
      </div>
      {Toast}
    </Shell>
  )
}
