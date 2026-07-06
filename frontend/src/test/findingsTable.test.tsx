import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FindingsTable } from '@/components/ui'

function makeFindings(count: number, severity = 'medium') {
  return Array.from({ length: count }, (_, i) => ({
    severity,
    package: `pkg-${i}`,
    summary: `Summary for pkg-${i}`,
    version: `1.0.${i}`,
  }))
}

describe('FindingsTable', () => {
  it('returns null for an empty findings array', () => {
    const { container } = render(<FindingsTable findings={[]} />)
    expect(container.firstChild).toBeNull()
  })

  it('renders a row for each finding (under page limit)', () => {
    render(<FindingsTable findings={makeFindings(3)} />)
    // match only the package name spans (exact text like "pkg-0"), not the summary text
    expect(screen.getAllByText(/^pkg-\d+$/)).toHaveLength(3)
  })

  it('sorts findings by severity: critical before high before medium', () => {
    const findings = [
      { severity: 'medium', package: 'medium-pkg', summary: '' },
      { severity: 'critical', package: 'critical-pkg', summary: '' },
      { severity: 'high', package: 'high-pkg', summary: '' },
    ]
    render(<FindingsTable findings={findings} />)
    const rows = screen.getAllByText(/\w+-pkg/)
    expect(rows[0]).toHaveTextContent('critical-pkg')
    expect(rows[1]).toHaveTextContent('high-pkg')
    expect(rows[2]).toHaveTextContent('medium-pkg')
  })

  it('does not show pagination for 25 or fewer findings', () => {
    render(<FindingsTable findings={makeFindings(25)} />)
    expect(screen.queryByText(/←/)).not.toBeInTheDocument()
    expect(screen.queryByText(/→/)).not.toBeInTheDocument()
  })

  it('shows pagination controls for more than 25 findings', () => {
    render(<FindingsTable findings={makeFindings(26)} />)
    expect(screen.getByText('←')).toBeInTheDocument()
    expect(screen.getByText('→')).toBeInTheDocument()
    expect(screen.getByText('1–25 of 26')).toBeInTheDocument()
  })

  it('navigates to the next page', async () => {
    const user = userEvent.setup()
    render(<FindingsTable findings={makeFindings(30)} />)
    expect(screen.queryByText('pkg-25')).not.toBeInTheDocument()
    await user.click(screen.getByText('→'))
    expect(screen.getByText('pkg-25')).toBeInTheDocument()
    expect(screen.getByText('26–30 of 30')).toBeInTheDocument()
  })

  it('disables the back button on the first page', () => {
    render(<FindingsTable findings={makeFindings(26)} />)
    expect(screen.getByText('←')).toBeDisabled()
  })

  it('disables the forward button on the last page', async () => {
    const user = userEvent.setup()
    render(<FindingsTable findings={makeFindings(26)} />)
    await user.click(screen.getByText('→'))
    expect(screen.getByText('→')).toBeDisabled()
  })

  it('expands a finding row when clicked', async () => {
    const user = userEvent.setup()
    const findings = [{ severity: 'high', package: 'vuln-pkg', summary: 'Bad thing', details: 'Detailed description here' }]
    render(<FindingsTable findings={findings} />)
    expect(screen.queryByText('Detailed description here')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /vuln-pkg — view details/i }))
    expect(screen.getByText('Detailed description here')).toBeInTheDocument()
  })

  it('collapses an expanded row when clicked again', async () => {
    const user = userEvent.setup()
    const findings = [{ severity: 'high', package: 'vuln-pkg', summary: '', details: 'Unique detail content' }]
    render(<FindingsTable findings={findings} />)
    const row = screen.getByRole('button', { name: /vuln-pkg — view details/i })
    await user.click(row)
    expect(screen.getByText('Unique detail content')).toBeInTheDocument()
    await user.click(row)
    expect(screen.queryByText('Unique detail content')).not.toBeInTheDocument()
  })

  it('shows fixed versions when present', async () => {
    const user = userEvent.setup()
    const findings = [{ severity: 'medium', package: 'fixable', summary: '', fixed_versions: ['2.0.0', '2.1.0'] }]
    render(<FindingsTable findings={findings} />)
    await user.click(screen.getByText('fixable'))
    expect(screen.getByText('2.0.0, 2.1.0')).toBeInTheDocument()
  })

  it('shows "No fix available" when fixed_versions is empty', async () => {
    const user = userEvent.setup()
    const findings = [{ severity: 'high', package: 'unfixed', summary: '', fixed_versions: [] }]
    render(<FindingsTable findings={findings} />)
    await user.click(screen.getByText('unfixed'))
    expect(screen.getByText('No fix available')).toBeInTheDocument()
  })
})
