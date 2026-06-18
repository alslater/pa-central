import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ErrorBoundary } from '@/components/ErrorBoundary'

function BombOnce({ shouldThrow }: { shouldThrow: boolean }) {
  if (shouldThrow) throw new Error('Test render error')
  return <div>All good</div>
}

beforeAll(() => {
  // Suppress console.error for expected thrown errors
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterAll(() => {
  vi.restoreAllMocks()
})

describe('ErrorBoundary', () => {
  it('renders children when no error is thrown', () => {
    render(
      <ErrorBoundary>
        <div>Hello</div>
      </ErrorBoundary>
    )
    expect(screen.getByText('Hello')).toBeInTheDocument()
  })

  it('renders the error UI when a child throws', () => {
    render(
      <ErrorBoundary>
        <BombOnce shouldThrow />
      </ErrorBoundary>
    )
    expect(screen.queryByText('All good')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument()
  })

  it('shows some error indication text', () => {
    render(
      <ErrorBoundary>
        <BombOnce shouldThrow />
      </ErrorBoundary>
    )
    // Should render some kind of error heading/message
    expect(document.body.textContent).toMatch(/error|went wrong|failed/i)
  })

  it('resets and re-renders children when Try Again is clicked', async () => {
    const user = userEvent.setup()
    let shouldThrow = true

    function Controlled() {
      if (shouldThrow) throw new Error('boom')
      return <div>Recovered</div>
    }

    const { rerender } = render(
      <ErrorBoundary>
        <Controlled />
      </ErrorBoundary>
    )

    expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument()

    // Fix the underlying component before clicking Try Again
    shouldThrow = false
    await user.click(screen.getByRole('button', { name: /try again/i }))

    rerender(
      <ErrorBoundary>
        <Controlled />
      </ErrorBoundary>
    )

    expect(screen.getByText('Recovered')).toBeInTheDocument()
  })
})
