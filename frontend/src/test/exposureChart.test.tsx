import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { ExposureChart } from '@/components/ExposureChart'
import type { ExposurePoint } from '@/lib/api'

const points: ExposurePoint[] = [
  { date: '2026-08-01', exposure: 0 },
  { date: '2026-08-02', exposure: 27 },
  { date: '2026-08-03', exposure: 81 },
]

describe('ExposureChart', () => {
  it('renders without crashing given multiple points', () => {
    render(<ExposureChart points={points} />)
    expect(screen.getByTestId('exposure-chart')).toBeInTheDocument()
  })

  it('renders without crashing given a single point', () => {
    render(<ExposureChart points={[points[0]]} />)
    expect(screen.getByTestId('exposure-chart')).toBeInTheDocument()
  })

  it('renders an empty state given zero points', () => {
    render(<ExposureChart points={[]} />)
    expect(screen.getByText(/no exposure history/i)).toBeInTheDocument()
  })
})
