import { render, screen } from '@testing-library/react'
import { SeverityBadge, StatusDot } from '@/components/ui'

describe('SeverityBadge', () => {
  it('renders the severity label', () => {
    render(<SeverityBadge severity="critical" />)
    expect(screen.getByText('critical')).toBeInTheDocument()
  })

  it('renders each severity without throwing', () => {
    const severities = ['critical', 'high', 'medium', 'warning', 'low', 'info'] as const
    for (const s of severities) {
      const { unmount } = render(<SeverityBadge severity={s} />)
      expect(screen.getByText(s)).toBeInTheDocument()
      unmount()
    }
  })
})

describe('StatusDot', () => {
  it('renders the status label', () => {
    render(<StatusDot status="running" />)
    expect(screen.getByText('running')).toBeInTheDocument()
  })
})
