import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ScanDetailTabs } from '@/components/ui'

const mockFindings = [{ package: 'flask', severity: 'high', advisory_id: 'GHSA-x' }]
const mockRisks = [{ package: 'reqeusts', ecosystem: 'pypi', score: 46, level: 'warning',
  signals: [{ name: 'typosquat', score: 15, reason: "resembles 'requests'" }] }]

describe('ScanDetailTabs', () => {
  it('returns null when both findings and risks are empty', () => {
    const { container } = render(<ScanDetailTabs findings={[]} risks={[]} />)
    expect(container.firstChild).toBeNull()
  })

  it('returns null when both are null/undefined', () => {
    const { container } = render(<ScanDetailTabs findings={null} risks={undefined} />)
    expect(container.firstChild).toBeNull()
  })

  it('renders the findings table directly with no tab bar when there are no risks', () => {
    render(<ScanDetailTabs findings={mockFindings} risks={[]} />)
    expect(screen.getByText('flask')).toBeInTheDocument()
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument()
    expect(screen.queryByRole('tab')).not.toBeInTheDocument()
  })

  it('renders the risks table directly with no tab bar when there are no findings', () => {
    render(<ScanDetailTabs findings={[]} risks={mockRisks} />)
    expect(screen.getByText('reqeusts')).toBeInTheDocument()
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument()
    expect(screen.queryByRole('tab')).not.toBeInTheDocument()
  })

  it('exposes a WAI-ARIA tablist and defaults to Findings when both are present', () => {
    render(<ScanDetailTabs findings={mockFindings} risks={mockRisks} />)
    expect(screen.getByRole('tablist')).toBeInTheDocument()
    const findingsTab = screen.getByRole('tab', { name: /findings \(1\)/i })
    const risksTab = screen.getByRole('tab', { name: /risks \(1\)/i })

    expect(findingsTab).toHaveAttribute('aria-selected', 'true')
    expect(findingsTab).toHaveAttribute('tabindex', '0')
    expect(risksTab).toHaveAttribute('aria-selected', 'false')
    expect(risksTab).toHaveAttribute('tabindex', '-1')

    expect(screen.getByText('flask')).toBeVisible()
    // The inactive panel is still mounted (for a11y panel association via
    // aria-controls/aria-labelledby) but hidden from the accessibility tree.
    const panels = screen.getAllByRole('tabpanel', { hidden: true })
    expect(panels).toHaveLength(2)
    const risksPanel = panels.find(p => p.getAttribute('aria-labelledby')?.includes('tab-risks'))!
    expect(risksPanel).not.toBeVisible()
  })

  it('switches to the risks table when the Risks tab is clicked', async () => {
    const user = userEvent.setup()
    render(<ScanDetailTabs findings={mockFindings} risks={mockRisks} />)

    await user.click(screen.getByRole('tab', { name: /risks \(1\)/i }))
    expect(screen.getByRole('tab', { name: /risks \(1\)/i })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByText('reqeusts')).toBeVisible()
    expect(screen.getByText('flask')).not.toBeVisible()

    await user.click(screen.getByRole('tab', { name: /findings \(1\)/i }))
    expect(screen.getByRole('tab', { name: /findings \(1\)/i })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByText('flask')).toBeVisible()
    expect(screen.getByText('reqeusts')).not.toBeVisible()
  })

  it('ArrowRight moves selection from Findings to Risks and focuses it', async () => {
    const user = userEvent.setup()
    render(<ScanDetailTabs findings={mockFindings} risks={mockRisks} />)

    const findingsTab = screen.getByRole('tab', { name: /findings \(1\)/i })
    const risksTab = screen.getByRole('tab', { name: /risks \(1\)/i })
    findingsTab.focus()
    await user.keyboard('{ArrowRight}')

    expect(risksTab).toHaveAttribute('aria-selected', 'true')
    expect(risksTab).toHaveAttribute('tabindex', '0')
    expect(findingsTab).toHaveAttribute('tabindex', '-1')
    expect(document.activeElement).toBe(risksTab)
  })

  it('ArrowLeft wraps from Findings to Risks', async () => {
    const user = userEvent.setup()
    render(<ScanDetailTabs findings={mockFindings} risks={mockRisks} />)

    const findingsTab = screen.getByRole('tab', { name: /findings \(1\)/i })
    const risksTab = screen.getByRole('tab', { name: /risks \(1\)/i })
    findingsTab.focus()
    await user.keyboard('{ArrowLeft}')

    expect(risksTab).toHaveAttribute('aria-selected', 'true')
    expect(findingsTab).toHaveAttribute('aria-selected', 'false')
  })
})
