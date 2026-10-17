import { render, screen } from '@testing-library/react'
// ui is imported FIRST on purpose: it imports FixPlanPanel, so FixPlanPanel's
// module-level constants must not depend on ui.tsx having finished loading.
import '@/components/ui'
import { FixPlanPanel } from '@/components/FixPlanPanel'
import type { FixPlanResult } from '@/lib/api'

it('builds the Verified tag classes when ui.tsx loads first', () => {
  const fp = { status: 'planned', lockfile: 'uv.lock', error: null, exit_code: 0, duration_seconds: 1,
    timeout_seconds: 900, near_timeout: false, plan: { lockfile: 'uv.lock', planned: [], held: [], commands: [],
    verified: true, unverified_reason: null, trial_failure: null, lock_drift: [], yanked_locked: [],
    osv_failures: 0, yank_failures: 0 } } as unknown as FixPlanResult
  render(<FixPlanPanel fixPlan={fp} />)
  const cls = screen.getByText('Verified').className
  expect(cls).toContain('inline-flex')
  expect(cls).toContain('text-status-pass-text')
  expect(cls).not.toContain('undefined')
})
