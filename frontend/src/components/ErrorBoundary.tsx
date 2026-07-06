import { Component, ReactNode } from 'react'

interface Props { children: ReactNode }
interface State { error: Error | null }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  render() {
    if (this.state.error) {
      return (
        <div className="error-boundary-wrap">
          <div className="error-boundary-title">Something went wrong</div>
          <pre className="error-boundary-pre">
            {this.state.error.message}
          </pre>
          <button
            type="button"
            onClick={() => this.setState({ error: null })}
            className="error-boundary-btn"
          >
            Try again
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
