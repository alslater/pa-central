import { Button, Empty, useToast } from '@/components/ui'
import { TAG_MUTED, TAG_PASS, TAG_REVIEW } from '@/components/tags'
import type { FixPlanResult, HeldFix, PlannedFix } from '@/lib/api'

export function formatDuration(seconds: number): string {
  const s = Math.round(seconds)
  const m = Math.floor(s / 60), r = s % 60
  if (!m) return `${r}s`
  return r ? `${m}m ${r}s` : `${m}m`
}

function shellJoin(argv: string[]): string {
  return argv.map(a => (/^[\w@%+=:,./-]+$/.test(a) ? a : `'${a.replace(/'/g, `'\\''`)}'`)).join(' ')
}

// plan.commands is list[Any] on the backend: keep only argv-shaped entries
// (arrays of strings) and ignore anything malformed.
function commandLines(commands: unknown[]): string[][] {
  return commands.filter((c): c is string[] => Array.isArray(c) && c.length > 0 && c.every(a => typeof a === 'string'))
}

function PlannedRow({ p }: { p: PlannedFix }) {
  const via = p.parent ? ` via ${p.parent.package} ${p.parent.version}` : ''
  return (
    <tr className="border-b border-border">
      <td className="px-3 py-2 font-mono text-xs font-semibold">{p.package ?? '—'}</td>
      <td className="px-3 py-2 font-mono text-xs">{`${p.version ?? '?'} → ${p.target ?? '?'}`}</td>
      <td className="px-3 py-2 text-xs">{p.direct ? 'direct' : `transitive${via}`}</td>
      <td className="px-3 py-2 text-xs">{p.advisories.length}</td>
      <td className="px-3 py-2"><div className="flex flex-wrap gap-1">
        {p.verified === false && <span className={TAG_REVIEW}>Unverified</span>}
        {p.left_open.length > 0 && (
          <span className={TAG_REVIEW} title={p.fixes_all ? `${p.fixes_all} fixes all of them` : undefined}>
            Leaves {p.left_open.length} open
          </span>
        )}
        {p.by_relock && <span className={TAG_MUTED}>By re-lock</span>}
      </div></td>
    </tr>
  )
}

function HeldRow({ h }: { h: HeldFix }) {
  return (
    <tr className="border-b border-border">
      <td className="px-3 py-2 font-mono text-xs font-semibold">{h.package ?? '—'}</td>
      <td className="px-3 py-2 font-mono text-xs">{h.version ?? '—'}</td>
      <td className="px-3 py-2 text-xs">{h.reason ?? '—'}</td>
      <td className="px-3 py-2 text-xs">
        {h.detail || null}
        {h.needs_major.length > 0 && (
          <span className="block text-muted-foreground">needs --allow-major {h.needs_major.join(',')}
            {h.cadence ? ` (${h.cadence})` : ''}</span>
        )}
      </td>
    </tr>
  )
}

export function FixPlanPanel({ fixPlan }: { fixPlan: FixPlanResult }) {
  const { show, Toast } = useToast()
  const plan = fixPlan.plan
  if (fixPlan.status !== 'planned' || !plan) {
    return <div className="px-4 py-3"><Empty message={fixPlan.error ?? 'No fix plan was produced'} /></div>
  }
  const commands = commandLines(plan.commands)
  const commandText = commands.map(shellJoin).join('\n')
  const copy = () => {
    // navigator.clipboard is undefined in insecure contexts; writeText would throw synchronously.
    if (!navigator.clipboard?.writeText) { show('Could not copy', 'err'); return }
    navigator.clipboard.writeText(commandText)
      .then(() => show('Commands copied'), () => show('Could not copy', 'err'))
  }
  return (
    <div className="flex flex-col gap-3 px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-xs font-semibold">{fixPlan.lockfile ?? plan.lockfile}</span>
        {plan.verified
          ? <span className={TAG_PASS}>Verified</span>
          : <span className={TAG_REVIEW} title={plan.unverified_reason ?? undefined}>Unverified</span>}
        {!plan.verified && plan.unverified_reason && (
          <span className="text-xs text-muted-foreground">{plan.unverified_reason}</span>
        )}
      </div>
      {plan.trial_failure && (
        <p className="text-xs text-status-review-text">Every trial failed the same way: {plan.trial_failure}</p>
      )}
      {commands.length > 0 && (
        <div className="flex flex-col gap-1">
          {plan.lock_drift_unchecked > 0 && (
            // As package-alert words it; its own --apply refuses such a plan.
            <p className="text-xs text-status-review-text">
              {plan.lock_drift_unchecked} version(s) that re-locking the project installs could not be checked for
              {' '}withdrawn releases.
            </p>
          )}
          {plan.separate && (
            // As package-alert prints it: the commands apply only the first fix.
            <p className="text-xs text-status-review-text">
              These fixes could not be verified as one command{plan.separate_reason ? `: ${plan.separate_reason}` : ''}.
              {' '}Only the first is printed.
            </p>
          )}
          <pre className="result-error-pre font-mono text-xs whitespace-pre-wrap">{commandText}</pre>
          <div><Button variant="secondary" onClick={copy}>Copy commands</Button></div>
          {plan.deferred.length > 0 && (
            <p className="text-xs text-status-review-text">
              Next, after applying that and re-running pa fix: {plan.deferred.join(', ')}
            </p>
          )}
        </div>
      )}
      {plan.planned.length > 0 && (
        <table className="w-full text-left">
          <caption className="text-style-caption text-left mb-1">Planned ({plan.planned.length})</caption>
          <thead><tr className="text-style-caption"><th scope="col" className="px-3">Package</th><th scope="col" className="px-3">Upgrade</th>
            <th scope="col" className="px-3">Dependency</th><th scope="col" className="px-3">Advisories</th><th scope="col" className="px-3">Notes</th></tr></thead>
          <tbody>{plan.planned.map((p, i) => <PlannedRow key={`${p.package}-${i}`} p={p} />)}</tbody>
        </table>
      )}
      {plan.held.length > 0 && (
        <table className="w-full text-left">
          <caption className="text-style-caption text-left mb-1">Held ({plan.held.length})</caption>
          <thead><tr className="text-style-caption"><th scope="col" className="px-3">Package</th><th scope="col" className="px-3">Version</th>
            <th scope="col" className="px-3">Reason</th><th scope="col" className="px-3">Detail</th></tr></thead>
          <tbody>{plan.held.map((h, i) => <HeldRow key={`${h.package}-${i}`} h={h} />)}</tbody>
        </table>
      )}
      {(plan.lock_drift.length > 0 || plan.yanked_locked.length > 0 || plan.osv_failures > 0 || plan.yank_failures > 0) && (
        <ul className="text-xs text-muted-foreground list-disc pl-5">
          {plan.lock_drift.length > 0 && <li>Re-locking also changes {plan.lock_drift.length} other package(s).</li>}
          {plan.yanked_locked.length > 0 && <li>{plan.yanked_locked.length} locked version(s) are yanked.</li>}
          {plan.osv_failures > 0 && <li>{plan.osv_failures} package(s) could not be checked against OSV.</li>}
          {plan.yank_failures > 0 && <li>{plan.yank_failures} package(s) could not be checked for yanks.</li>}
        </ul>
      )}
      {Toast}
    </div>
  )
}
