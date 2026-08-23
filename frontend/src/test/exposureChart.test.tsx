import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { ExposureChart } from '@/components/ExposureChart'
import type { ExposurePoint } from '@/lib/api'

// recharts' ResponsiveContainer reads getBoundingClientRect() on mount to
// size itself; jsdom always returns an all-zero rect, so the chart body
// never renders without this — which is also why the pre-existing "renders
// without crashing" tests below never actually exercised the chart's DOM
// output. Scoped to a single test (not file-wide) because rendering the
// real chart body with animation active recurses infinitely against
// setup.ts's synchronous requestAnimationFrame stub — a pre-existing,
// unrelated test-environment gap, not something to fix as part of this
// accessibility change.
function withRenderedChartBody<T>(fn: () => T): T {
  const original = Element.prototype.getBoundingClientRect
  Element.prototype.getBoundingClientRect = () => ({
    width: 400, height: 180, top: 0, left: 0, right: 400, bottom: 180,
    x: 0, y: 0, toJSON: () => {},
  })
  try {
    return fn()
  } finally {
    Element.prototype.getBoundingClientRect = original
  }
}

const points: ExposurePoint[] = [
  { date: '2026-08-01', exposure: 0 },
  { date: '2026-08-02', exposure: 27 },
  { date: '2026-08-03', exposure: 81 },
]

const TITLE = 'Exposure over time for test-repo'

describe('ExposureChart', () => {
  it('renders without crashing given multiple points', () => {
    render(<ExposureChart points={points} title={TITLE} />)
    expect(screen.getByTestId('exposure-chart')).toBeInTheDocument()
  })

  it('renders without crashing given a single point', () => {
    render(<ExposureChart points={[points[0]]} title={TITLE} />)
    expect(screen.getByTestId('exposure-chart')).toBeInTheDocument()
  })

  it('renders an empty state given zero points', () => {
    render(<ExposureChart points={[]} title={TITLE} />)
    expect(screen.getByText(/no exposure history/i)).toBeInTheDocument()
  })

  it('is keyboard-focusable via recharts accessibilityLayer, with an accessible name', () => {
    // Without accessibilityLayer, the chart is pure SVG with a hover-only
    // tooltip — unreachable by keyboard and unannounced to screen readers.
    // accessibilityLayer gives the chart surface role="application" and
    // tabindex="0", and wires arrow-key navigation between data points.
    // `title` renders as the SVG's own <title> child, which is what gives
    // that now-focusable region an accessible name — a visible page caption
    // alone isn't enough, since it's not programmatically associated with
    // the SVG for a screen reader to announce.
    //
    // Rendered with a single point (isAnimationActive={false} in that case)
    // to avoid recharts' animation driver recursing against jsdom's
    // synchronous requestAnimationFrame stub — an unrelated test-environment
    // limitation, not something this assertion needs multiple points for.
    withRenderedChartBody(() => render(<ExposureChart points={[points[0]]} title={TITLE} />))
    const chart = screen.getByTestId('exposure-chart')
    const focusable = chart.querySelector('[role="application"]')
    expect(focusable).not.toBeNull()
    expect(focusable).toHaveAttribute('tabindex', '0')
    expect(focusable).toHaveAccessibleName(TITLE)
  })
})
