import type { Remediation, Scan, ToolEntry, ToolProvenance } from '@/lib/api'
import { ScanDetailTabs, yankedOf } from '@/components/ui'
import { TAG_MUTED, TAG_REVIEW } from '@/components/tags'

// A `pa scan-tools` scan (pa-central #26): one per pipx or uv tools directory. Its findings,
// risks and remediations each carry the `source` of the tool they came from ("pipx:awscli"),
// so each tool shows only its own; one whose source names no listed tool is still shown.

export function isToolsScan(scan: Scan): boolean {
  return scan.scan_type === 'tools'
}

/** Whether the card has anything to expand into: tools, directories that were not checked,
 *  findings, risks or yanked versions. */
export function toolsScanHasDetail(scan: Scan): boolean {
  return !!scan.tools?.length || !!scan.unchecked?.length || !!scan.findings?.length || !!scan.risks?.length
    || yankedOf(scan).length > 0
}

/** The card row's chips for a tools scan: manager, layout state, tool count, unchecked dirs. */
export function ToolsScanChips({ scan, chipClass }: { scan: Scan; chipClass: string }) {
  const unchecked = scan.unchecked ?? []
  const tools = scan.tools ?? []
  return (
    <>
      {!scan.active && (
        <span className={TAG_REVIEW}
              title="pipx no longer uses this layout, but its venvs still hold the code below.">
          leftover layout, pipx no longer uses it
        </span>
      )}
      {!scan.exists && !tools.length
        ? <span className={chipClass} title="The scan found no tools directory for this manager">no {scan.manager ?? ''} tools</span>
        : <span className={chipClass}>{tools.length} tool{tools.length !== 1 ? 's' : ''}</span>}
      {unchecked.length > 0 && (
        <span className={`${chipClass} has-findings`}
              title={`${unchecked.length} director${unchecked.length !== 1 ? 'ies' : 'y'} whose packages were not checked: this scan is not a clean result`}>
          ⚠ {unchecked.length} not checked
        </span>
      )}
    </>
  )
}

export function ManagerTag({ manager }: { manager: string | null }) {
  return manager ? <span className="source-tag">{manager}</span> : null
}

function sourceOf(tool: ToolEntry, scan: Scan): string {
  return `${tool.manager ?? scan.manager}:${tool.name}`
}

function bySource<T>(rows: T[] | null | undefined, source: string): T[] {
  return (rows ?? []).filter(r => (r as { source?: unknown }).source === source)
}

export function ToolsScanPanel({ scan }: { scan: Scan }) {
  const tools = scan.tools ?? []
  const unchecked = scan.unchecked ?? []
  const yanked = yankedOf(scan)
  const known = new Set(tools.map(t => sourceOf(t, scan)))
  // Unmatched rows stay grouped by source: one table of several sources would show only the
  // first source's remediation for a package they share.
  const unmatchedSources = [...new Set(
    [...scan.findings ?? [], ...scan.risks ?? []]
      .map(r => (r as { source?: unknown }).source)
      .filter((src): src is string => typeof src === 'string' && !known.has(src)),
  )]
  const noSource = <T,>(rows: T[] | null | undefined) =>
    (rows ?? []).filter(r => typeof (r as { source?: unknown }).source !== 'string')
  const other = [
    ...unmatchedSources.map(src => ({
      label: src, findings: bySource(scan.findings, src), risks: bySource(scan.risks, src),
      remediations: bySource<Remediation>(scan.remediations, src),
    })),
    { label: 'no source', findings: noSource(scan.findings), risks: noSource(scan.risks),
      remediations: noSource<Remediation>(scan.remediations) },
  ].filter(g => g.findings.length > 0 || g.risks.length > 0)
  return (
    <div className="flex flex-col">
      {unchecked.length > 0 && (
        <div className="px-4 py-2.5 border-b border-border">
          <div className="text-style-body-small text-status-review-text">
            ⚠ Not checked, so this scan is not a clean result:
          </div>
          <ul className="text-style-body-small font-mono">
            {unchecked.map(d => <li key={d}>{d}</li>)}
          </ul>
        </div>
      )}
      {tools.map(t => {
        const source = sourceOf(t, scan)
        return (
          <ToolGroup key={source} tool={t} risksReported={scan.risks != null}
                     findings={bySource(scan.findings, source)} risks={bySource(scan.risks, source)}
                     remediations={bySource(scan.remediations, source)} />
        )
      })}
      {other.map(g => (
        <div key={g.label} role="group" aria-label={`other findings ${g.label}`} className="border-b border-border">
          <div className="px-4 py-2.5 text-style-body-small text-muted-foreground">
            Not matched to a listed tool: <span className="font-mono">{g.label}</span>
          </div>
          <ScanDetailTabs findings={g.findings} risks={g.risks} remediations={g.remediations} />
        </div>
      ))}
      {yanked.length > 0 && (
        <div role="group" aria-label="yanked versions" className="border-b border-border">
          <ScanDetailTabs findings={[]} risks={[]} yanked={yanked} />
        </div>
      )}
    </div>
  )
}

function ToolGroup({ tool, risksReported, findings, risks, remediations }: {
  tool: ToolEntry
  /** False when the scan reported no risk pass: no risks then means unknown, not none. True
   *  does not prove the pass ran either (--no-risk sends an empty list), hence "reported". */
  risksReported: boolean
  findings: Record<string, unknown>[]
  risks: Record<string, unknown>[]
  remediations: Remediation[]
}) {
  return (
    <div role="group" aria-label={`tool ${tool.name}`} className="border-b border-border">
      <div className="flex flex-wrap items-center gap-2.5 px-4 py-2.5 bg-muted/30">
        <span className="text-style-body-small font-semibold">{tool.name}</span>
        {tool.version && <span className="font-mono text-xs">{tool.version}</span>}
        {tool.python && <span className="text-xs text-muted-foreground">Python {tool.python}</span>}
        <ProvenanceTags provenance={tool.provenance} />
      </div>
      {tool.orphaned.length > 0 && (
        <div className="px-4 py-1.5 text-style-body-small text-muted-foreground">
          Another interpreter's directory, not scanned:
          <ul className="font-mono">{tool.orphaned.map(d => <li key={d}>{d}</li>)}</ul>
        </div>
      )}
      {tool.unchecked.length > 0 && (
        <div className="px-4 py-1.5 text-style-body-small text-status-review-text">
          ⚠ Not checked:
          <ul className="font-mono">{tool.unchecked.map(d => <li key={d}>{d}</li>)}</ul>
        </div>
      )}
      {findings.length > 0 || risks.length > 0
        ? <ScanDetailTabs findings={findings} risks={risks} remediations={remediations} />
        : <div className="px-4 py-1.5 text-style-body-small text-muted-foreground">
            {risksReported ? 'No findings or risks reported.' : 'No findings. Risks unavailable.'}
          </div>}
    </div>
  )
}

function ProvenanceTags({ provenance }: { provenance: ToolProvenance | null }) {
  if (!provenance) return null
  const { kind, editable, path, url, index_source, extra_index } = provenance
  return (
    <>
      {kind === 'local' && (
        <span className={TAG_MUTED} title={path ? `Installed from ${path}` : undefined}>
          local checkout, not looked up (dependencies checked)
        </span>
      )}
      {kind === 'index' && (
        <span className={TAG_MUTED} title={url ? `Installed from ${url}; its packages were not looked up publicly` : 'Its packages were not looked up publicly'}>
          private index
        </span>
      )}
      {(kind === 'git' || kind === 'url') && (
        <span className={TAG_MUTED} title={url ? `Installed from ${url}; the app itself was not looked up publicly` : undefined}>
          {kind}
        </span>
      )}
      {kind === 'unknown' && (
        <span className={TAG_MUTED} title="No readable pipx or uv record of where it came from; its packages were looked up publicly">
          no install record
        </span>
      )}
      {editable && <span className={TAG_MUTED}>editable</span>}
      {index_source === 'config' && (
        <span className={TAG_MUTED}
              title="pip or uv configuration at scan time, not the recorded install, kept these packages from public lookup. The install may have used different settings.">
          index from pip/uv config
        </span>
      )}
      {extra_index && (
        <span className={TAG_MUTED} title="An extra index sat beside PyPI; the packages were still looked up publicly">
          extra index
        </span>
      )}
    </>
  )
}
