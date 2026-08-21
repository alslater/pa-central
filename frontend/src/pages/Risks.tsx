import React, { useCallback, useEffect, useState } from 'react'
import { api, RiskRecord, RiskSortKey, SortDir } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Button, Card, Drawer, Empty, RiskAcceptForm, RiskRecordDetail, RiskRevokeButton, Select, RiskLevelBadge, useToast } from '@/components/ui'
import { useLocalStorage } from '@/lib/hooks'

const LEVELS: ('critical' | 'warning' | 'info')[] = ['critical', 'warning', 'info']
const PAGE_SIZE = 50
// Data columns only; the actions column is rendered separately with an sr-only
// label. The expanded detail row spans the whole table, so its colSpan derives
// from this count plus that actions column.
const COLUMNS = ['Repo', 'Level', 'Package', 'Ecosystem', 'Score', 'Open since', 'Status'] as const
const COLUMN_COUNT = COLUMNS.length + 1

type AcceptedFilter = 'all' | 'accepted'

function RiskDetailPanel({ risk: r }: { risk: RiskRecord }) {
  return <RiskRecordDetail r={r} />
}

export default function Risks() {
  const [risks, setRisks] = useState<RiskRecord[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [levelFilter, setLevelFilter] = useLocalStorage<('critical' | 'warning' | 'info')[]>('risks-level-filter', [])
  const [acceptedFilter, setAcceptedFilter] = useLocalStorage<AcceptedFilter>('risks-accepted-filter', 'all')
  const [sortKey, setSortKey] = useState<RiskSortKey>('level')
  // level asc already puts the most urgent level first (_LEVEL_RANK ranks
  // critical=0). days_open and score both need desc to lead with the most
  // urgent record — oldest open, or highest score — since there's no
  // direction selector in the UI for the user to choose otherwise.
  const sortDir: SortDir = (sortKey === 'days_open' || sortKey === 'score') ? 'desc' : 'asc'
  const [page, setPage] = useState(0)
  const [acceptingId, setAcceptingId] = useState<number | null>(null)
  const [selectedRisk, setSelectedRisk] = useState<RiskRecord | null>(null)
  const { show, Toast } = useToast()

  const reqSeq = React.useRef(0)
  // Mirrors `page` for callbacks that fire long after their render — the
  // accept/revoke `onDone` handlers run only once an awaited request resolves,
  // by which time the user may have paged away. Reading the ref refreshes
  // whatever page is showing now, rather than refetching the captured page and
  // overwriting the table with rows the pager no longer claims to display.
  // Written in an effect, not during render (a discarded render must not mutate
  // it); declared before the pagination effect so it commits first.
  // Not useEffectEvent: that can only be *called* from effects, and these are
  // event handlers.
  const pageRef = React.useRef(page)
  useEffect(() => { pageRef.current = page }, [page])

  // `page` is passed in rather than closed over, so `load` doesn't rebuild on
  // every page change. Its identity therefore changes only when the filters or
  // sort change, which the pagination effect below relies on.
  const load = useCallback(async (pageArg: number, background = false) => {
    const seq = ++reqSeq.current
    if (background) setRefreshing(true)
    else setLoading(true)
    try {
      const data = await api.risks.list({
        level: levelFilter.length ? levelFilter : undefined,
        accepted: acceptedFilter === 'accepted' ? true : undefined,
        page: pageArg,
        page_size: PAGE_SIZE,
        sort: sortKey,
        sort_dir: sortDir,
      })
      if (seq !== reqSeq.current) return
      setRisks(data.items)
      setTotal(data.total)
      setSelectedRisk(prev => {
        if (!prev) return null
        // Update the selected risk if it's on the current page (picks up
        // any field changes from the refresh). If it's on a different page,
        // preserve the previous value — it still exists, just isn't visible here.
        const refreshed = data.items.find(r => r.id === prev.id)
        return refreshed ?? prev
      })
    } catch (e: any) {
      if (seq !== reqSeq.current) return
      show(e.message ?? 'Failed to load risks', 'err')
    } finally {
      if (seq === reqSeq.current) {
        setLoading(false)
        setRefreshing(false)
      }
    }
  }, [levelFilter, acceptedFilter, sortKey, sortDir, show])

  // Pagination effect: fires when load rebuilds (filter/sort change) or page changes.
  // When load rebuilds and page > 0: reset page to 0 and skip the fetch — the
  // page change re-triggers this effect and the fetch happens then (page 0, one request).
  // When load rebuilds and page is already 0, or when only page changes (navigation):
  // fetch immediately using the current page.
  // The load-identity comparison lives inside the effect: deriving it during
  // render and advancing the ref there would consume the "load changed" signal
  // on a render that may never commit, silently losing the page reset.
  const prevLoadRef = React.useRef(load)
  useEffect(() => {
    const filterReset = prevLoadRef.current !== load
    prevLoadRef.current = load
    if (filterReset) {
      setAcceptingId(null)
      if (page !== 0) {
        // eslint-disable-next-line react-hooks/set-state-in-effect -- intentional: setPage(0) re-triggers this effect which does the fetch
        setPage(0)
        return
      }
    }
    load(page)
    // reqSeq is an abort counter: incrementing in cleanup invalidates in-flight responses so stale data is never committed.
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reading reqSeq.current in cleanup is intentional; "stale ref" warning doesn't apply to a counter ref (not a DOM node)
    return () => { reqSeq.current++ }
    // page is included so pagination (prev/next) triggers a fetch.
  }, [load, page])

  const totalPages = Math.ceil(total / PAGE_SIZE)
  // Clamp page after a background refresh shrinks total (e.g. accept/revoke).
  // Also resets to 0 when the result set empties entirely (totalPages === 0).
  // eslint-disable-next-line react-hooks/set-state-in-effect -- clamps page to valid range when data shrinks; derived-state reset pattern
  useEffect(() => { setPage(p => totalPages > 0 ? Math.min(p, totalPages - 1) : 0) }, [totalPages])

  const paged = risks

  return (
    <Shell>
      <PageHeader
        title="Risks"
        subtitle="Open risk signals across all repo scans"
      />
      <div className="p-6 px-7 overflow-auto">

        {/* Filter bar */}
        <div className="flex flex-wrap gap-2.5 mb-4 items-center">
          <div className="flex gap-1">
            {LEVELS.map(l => (
              <button
                key={l}
                type="button"
                aria-pressed={levelFilter.includes(l) ? true : false}
                onClick={() => setLevelFilter(prev => prev.includes(l) ? prev.filter(x => x !== l) : [...prev, l])}
                className={`px-2 py-0.5 rounded text-style-tag border transition-colors ${
                  levelFilter.includes(l)
                    ? 'bg-foreground text-background border-foreground'
                    : 'bg-muted text-muted-foreground border-border hover:border-foreground/40'
                }`}
              >
                {l}
              </button>
            ))}
          </div>
          <Select
            value={acceptedFilter}
            onChange={e => setAcceptedFilter(e.target.value as AcceptedFilter)}
            className="w-44"
          >
            <option value="all">All risks</option>
            <option value="accepted">Accepted</option>
          </Select>
          <Select
            value={sortKey}
            onChange={e => setSortKey(e.target.value as RiskSortKey)}
            className="w-44"
          >
            <option value="level">Sort: Level</option>
            <option value="days_open">Sort: Days open</option>
            <option value="repo">Sort: Repo</option>
            <option value="score">Sort: Score</option>
          </Select>
          <span className="text-[13px] text-muted-foreground ml-auto">
            {total} risks{refreshing && <span className="ml-1 opacity-50">·</span>}
          </span>
        </div>

        {loading ? (
          <div className="text-muted-foreground text-[13px]">Loading…</div>
        ) : total === 0 ? (
          <Empty message="No open risks match your filters." />
        ) : (
          <>
            <Card>
              <div className="overflow-x-auto">
                <table className="w-full border-collapse">
                  <thead>
                    <tr className="border-b border-border">
                      {COLUMNS.map(h => (
                        <th key={h} scope="col" className="text-left px-4 py-2.5 text-style-caption">{h}</th>
                      ))}
                      <th scope="col" className="px-4 py-2.5"><span className="sr-only">Actions</span></th>
                    </tr>
                  </thead>
                  <tbody>
                    {paged.map(r => (
                      <React.Fragment key={r.id}>
                        <tr
                          className="border-b border-border/50 hover:bg-muted/40 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand"
                          tabIndex={0}
                          role="button"
                          aria-label={`${r.package} — view details`}
                          onClick={() => setSelectedRisk(r)}
                          onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelectedRisk(r) } }}
                        >
                          <td className="px-4 py-2.5 text-[11px] text-muted-foreground whitespace-nowrap">{r.scan_name ?? '—'}</td>
                          <td className="px-4 py-2.5"><RiskLevelBadge level={r.level} /></td>
                          <td className="px-4 py-2.5">
                            <span className="font-mono text-xs font-medium">{r.package}</span>
                            {r.reopen_count > 0 && (
                              <span className="ml-1.5 text-[11px] text-status-review-text" title={`Reopened ${r.reopen_count} time(s)`}>↩×{r.reopen_count}</span>
                            )}
                          </td>
                          <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{r.ecosystem || '—'}</td>
                          <td className="px-4 py-2.5 font-mono text-[11px] text-muted-foreground">{r.score}</td>
                          <td className="px-4 py-2.5 text-[11px] font-medium text-muted-foreground">
                            {r.days_open}d
                          </td>
                          <td className="px-4 py-2.5">
                            {r.is_accepted ? (
                              <span
                                className="inline-flex items-center px-2 py-0.5 rounded text-style-tag bg-status-info/12 text-status-info-text"
                                title={`${r.accepted_reason ?? ''}${r.accepted_until ? ` — until ${r.accepted_until}` : ''}`}
                              >
                                Accepted
                              </span>
                            ) : (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-style-tag bg-muted text-muted-foreground">
                                Open
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-2.5" onClick={e => e.stopPropagation()} onKeyDown={e => e.stopPropagation()}>
                            {r.is_accepted ? (
                              <RiskRevokeButton risk={r} onDone={() => load(pageRef.current, true)} show={show} size="sm" />
                            ) : (
                              <Button
                                variant="ghost"
                                onClick={() => setAcceptingId(r.id)}
                                className="text-[11px] px-2.5 h-7"
                              >
                                Accept
                              </Button>
                            )}
                          </td>
                        </tr>
                        {acceptingId === r.id && (
                          <tr className="border-b border-border/50">
                            <td colSpan={COLUMN_COUNT} className="px-4 py-3 bg-muted/40">
                              <RiskAcceptForm
                                risk={r}
                                onDone={() => { setAcceptingId(null); load(pageRef.current, true) }}
                                onCancel={() => setAcceptingId(null)}
                                show={show}
                                size="sm"
                              />
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>

            {totalPages > 1 && (
              <div className="flex gap-2 mt-3 justify-end items-center">
                <Button variant="secondary" disabled={page === 0} onClick={() => setPage(p => p - 1)} className="px-2.5 h-8 text-xs">←</Button>
                <span className="text-[13px] text-muted-foreground">Page {page + 1} of {totalPages}</span>
                <Button variant="secondary" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)} className="px-2.5 h-8 text-xs">→</Button>
              </div>
            )}
          </>
        )}
      </div>
      {selectedRisk && (
        <Drawer
          title={selectedRisk.package}
          onClose={() => setSelectedRisk(null)}
        >
          <RiskDetailPanel risk={selectedRisk} />
        </Drawer>
      )}
      {Toast}
    </Shell>
  )
}
