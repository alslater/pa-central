import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { RisksTable } from '@/components/ui'

function makeRisks(count: number, level = 'warning') {
  return Array.from({ length: count }, (_, i) => ({
    level,
    package: `pkg-${i}`,
    ecosystem: 'pypi',
    version: `1.0.${i}`,
    score: 50,
  }))
}

describe('RisksTable', () => {
  it('returns null for an empty risks array', () => {
    const { container } = render(<RisksTable risks={[]} />)
    expect(container.firstChild).toBeNull()
  })

  it('renders a row for each risk (under page limit)', () => {
    render(<RisksTable risks={makeRisks(3)} />)
    // match only the package name spans (exact text like "pkg-0"), not other text
    expect(screen.getAllByText(/^pkg-\d+$/)).toHaveLength(3)
  })

  it('sorts risks by level: critical before warning before info', () => {
    const risks = [
      { level: 'info', package: 'info-pkg', ecosystem: 'pypi' },
      { level: 'critical', package: 'critical-pkg', ecosystem: 'pypi' },
      { level: 'warning', package: 'warning-pkg', ecosystem: 'pypi' },
    ]
    render(<RisksTable risks={risks} />)
    const rows = screen.getAllByText(/\w+-pkg/)
    expect(rows[0]).toHaveTextContent('critical-pkg')
    expect(rows[1]).toHaveTextContent('warning-pkg')
    expect(rows[2]).toHaveTextContent('info-pkg')
  })

  it('does not show pagination for 25 or fewer risks', () => {
    render(<RisksTable risks={makeRisks(25)} />)
    expect(screen.queryByText(/←/)).not.toBeInTheDocument()
    expect(screen.queryByText(/→/)).not.toBeInTheDocument()
  })

  it('shows pagination controls for more than 25 risks', () => {
    render(<RisksTable risks={makeRisks(26)} />)
    expect(screen.getByText('←')).toBeInTheDocument()
    expect(screen.getByText('→')).toBeInTheDocument()
    expect(screen.getByText('1–25 of 26')).toBeInTheDocument()
  })

  it('navigates to the next page', async () => {
    const user = userEvent.setup()
    render(<RisksTable risks={makeRisks(30)} />)
    expect(screen.queryByText('pkg-25')).not.toBeInTheDocument()
    await user.click(screen.getByText('→'))
    expect(screen.getByText('pkg-25')).toBeInTheDocument()
    expect(screen.getByText('26–30 of 30')).toBeInTheDocument()
  })

  it('disables the back button on the first page', () => {
    render(<RisksTable risks={makeRisks(26)} />)
    expect(screen.getByText('←')).toBeDisabled()
  })

  it('disables the forward button on the last page', async () => {
    const user = userEvent.setup()
    render(<RisksTable risks={makeRisks(26)} />)
    await user.click(screen.getByText('→'))
    expect(screen.getByText('→')).toBeDisabled()
  })

  it('expands a risk row when clicked and shows its signals', async () => {
    const user = userEvent.setup()
    const risks = [{
      level: 'warning',
      package: 'reqeusts',
      ecosystem: 'pypi',
      score: 46,
      signals: [{ name: 'typosquat', score: 15, reason: "resembles 'requests'" }],
    }]
    render(<RisksTable risks={risks} />)
    expect(screen.queryByText('typosquat')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /reqeusts — view details/i }))
    expect(screen.getByText('typosquat')).toBeInTheDocument()
    expect(screen.getByText(/resembles 'requests'/)).toBeInTheDocument()
  })

  it('collapses an expanded row when clicked again', async () => {
    const user = userEvent.setup()
    const risks = [{
      level: 'warning',
      package: 'vuln-pkg',
      ecosystem: 'pypi',
      signals: [{ name: 'unique-signal', score: 5, reason: 'unique reason text' }],
    }]
    render(<RisksTable risks={risks} />)
    const row = screen.getByRole('button', { name: /vuln-pkg — view details/i })
    await user.click(row)
    expect(screen.getByText('unique reason text', { exact: false })).toBeInTheDocument()
    await user.click(row)
    expect(screen.queryByText('unique reason text', { exact: false })).not.toBeInTheDocument()
  })

  it('clamps to the last page when a risks update shrinks the page count', async () => {
    const user = userEvent.setup()
    const { rerender } = render(<RisksTable risks={makeRisks(60)} />)
    // 3 pages of 25 — move to the last page (page index 2).
    await user.click(screen.getByText('→'))
    await user.click(screen.getByText('→'))
    expect(screen.getByText('pkg-50')).toBeInTheDocument()

    // Shrink to a single page: page 2 is now out of range.
    rerender(<RisksTable risks={makeRisks(10)} />)

    await waitFor(() => expect(screen.getByText('pkg-0')).toBeInTheDocument())
    expect(screen.queryByText(/←/)).not.toBeInTheDocument()
    expect(screen.queryByText(/→/)).not.toBeInTheDocument()
  })

  it('clamps to page 0 when a risks update empties the list entirely', async () => {
    const user = userEvent.setup()
    const { container, rerender } = render(<RisksTable risks={makeRisks(30)} />)
    await user.click(screen.getByText('→'))
    expect(screen.getByText('pkg-25')).toBeInTheDocument()

    rerender(<RisksTable risks={[]} />)

    await waitFor(() => expect(container.firstChild).toBeNull())
  })

  it('shows the score in the detail view when present', async () => {
    const user = userEvent.setup()
    const risks = [{ level: 'critical', package: 'scored-pkg', ecosystem: 'npm', score: 87 }]
    render(<RisksTable risks={risks} />)
    await user.click(screen.getByText('scored-pkg'))
    expect(screen.getAllByText(/Score\s*87/).length).toBeGreaterThan(0)
  })
})
