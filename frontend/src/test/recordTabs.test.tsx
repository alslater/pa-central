import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { RecordTabs } from '@/components/ui'
import type { FindingRecord, RiskRecord } from '@/lib/api'

const finding: FindingRecord = {
  id: 1, repo_scan_id: 1, advisory_id: 'GHSA-1', package: 'requests',
  ecosystem: 'pypi', severity: 'high', first_found_at: '2026-01-01T00:00:00Z',
  closed_at: null, closed_reason: null, reopen_count: 0,
  accepted_by_id: null, accepted_at: null, accepted_reason: null, accepted_until: null,
  summary: null, details: null, package_version: null, fixed_versions: null,
  url: null, is_malicious: null, is_accepted: false, days_open: 3,
  sla_days: 14, in_breach: false, scan_name: 'repo-a',
}

const risk: RiskRecord = {
  id: 1, repo_scan_id: 1, package: 'lodash', ecosystem: 'npm',
  package_version: '1.0.0', score: 70, level: 'warning', signals: [],
  first_found_at: '2026-01-01T00:00:00Z', closed_at: null, closed_reason: null,
  reopen_count: 0, accepted_by_id: null, accepted_at: null,
  accepted_reason: null, accepted_until: null, is_accepted: false,
  days_open: 3, scan_name: 'repo-a',
}

describe('RecordTabs', () => {
  it('renders a tablist with roving tabindex when both findings and risks are present', () => {
    render(<RecordTabs findings={[finding]} risks={[risk]} show={vi.fn()} />)
    const tablist = screen.getByRole('tablist')
    expect(tablist).toBeInTheDocument()
    const tabs = screen.getAllByRole('tab')
    expect(tabs).toHaveLength(2)
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true')
    expect(tabs[1]).toHaveAttribute('tabIndex', '-1')
  })

  it('collapses to no tab bar when only findings are present', () => {
    render(<RecordTabs findings={[finding]} risks={[]} show={vi.fn()} />)
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument()
    expect(screen.getByText('requests')).toBeInTheDocument()
  })

  it('switches panels on click and updates aria-selected', () => {
    render(<RecordTabs findings={[finding]} risks={[risk]} show={vi.fn()} />)
    const tabs = screen.getAllByRole('tab')
    fireEvent.click(tabs[1])
    expect(tabs[1]).toHaveAttribute('aria-selected', 'true')
    expect(tabs[0]).toHaveAttribute('aria-selected', 'false')
  })
})
