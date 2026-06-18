import { useId } from 'react'

const TZ_LIST = typeof Intl !== 'undefined' && 'supportedValuesOf' in Intl
  ? (Intl as any).supportedValuesOf('timeZone') as string[]
  : ['UTC']

interface Props {
  label?: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
}

export function TimezoneField({ label = 'Timezone', value, onChange, placeholder }: Props) {
  const datalistId = useId()
  return (
    <label className="flex flex-col gap-1">
      <span className="text-xs text-muted-foreground font-medium">{label}</span>
      <input
        list={datalistId}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder ?? 'e.g. Europe/London'}
        spellCheck={false}
        className="bg-muted border border-border rounded-[var(--radius-sm)] text-foreground px-2.5 py-[7px] text-[13px] outline-none w-full"
      />
      <datalist id={datalistId}>
        {TZ_LIST.map(tz => <option key={tz} value={tz} />)}
      </datalist>
    </label>
  )
}
