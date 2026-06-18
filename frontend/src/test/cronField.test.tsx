import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CronField } from '@/components/CronField'

describe('CronField', () => {
  it('renders the input with the current value', () => {
    render(<CronField value="0 * * * *" onChange={() => {}} />)
    expect(screen.getByRole('textbox')).toHaveValue('0 * * * *')
  })

  it('shows a human-readable description for a valid expression', () => {
    render(<CronField value="0 9 * * 1" onChange={() => {}} />)
    // cronstrue renders something like "At 09:00 AM, only on Monday"
    expect(screen.getByText(/monday/i)).toBeInTheDocument()
  })

  it('shows next 10 executions for a valid expression', () => {
    render(<CronField value="0 * * * *" onChange={() => {}} />)
    expect(screen.getByText(/next 10 executions/i)).toBeInTheDocument()
    // 10 numbered rows
    expect(screen.getAllByText(/^\d+\.$/)).toHaveLength(10)
  })

  it('shows an error for an invalid expression', () => {
    render(<CronField value="not a cron" onChange={() => {}} />)
    expect(screen.queryByText(/next 10 executions/i)).not.toBeInTheDocument()
    // some error text should appear
    const input = screen.getByRole('textbox')
    expect(input).toBeInTheDocument()
    // error message sibling exists
    const container = input.closest('div')!.parentElement!
    expect(container.textContent).toMatch(/invalid|error|expression/i)
  })

  it('shows nothing extra for an empty value', () => {
    render(<CronField value="" onChange={() => {}} />)
    expect(screen.queryByText(/next 10 executions/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/invalid/i)).not.toBeInTheDocument()
  })

  it('calls onChange when the user types', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<CronField value="" onChange={onChange} />)
    await user.type(screen.getByRole('textbox'), '0')
    expect(onChange).toHaveBeenCalled()
  })

  it('calls onChange with the preset value when a preset is selected', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<CronField value="" onChange={onChange} />)
    await user.selectOptions(screen.getByRole('combobox', { name: /presets/i }), '0 * * * *')
    expect(onChange).toHaveBeenCalledWith('0 * * * *')
  })
})
