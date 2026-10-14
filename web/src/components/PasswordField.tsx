import { useLocalization } from '@fluent/react'
import { useState } from 'react'
import { TextField, type TextFieldProps } from './TextField'
import { TinyButton } from './TinyButton'

const FIELD_STYLE = { display: 'grid', gap: 4, justifyItems: 'start' } as const

/**
 * A password input with a reveal toggle (ASVS 2.1.12). The value stays masked
 * until the toggle is pressed; the toggle is a real button, so it is in the tab
 * order, and `aria-pressed` carries the state.
 */
export function PasswordField(props: Omit<TextFieldProps, 'type'>) {
  const { l10n } = useLocalization()
  const [revealed, setRevealed] = useState(false)
  return (
    <div style={FIELD_STYLE}>
      <TextField {...props} type={revealed ? 'text' : 'password'} />
      <TinyButton
        on={revealed}
        onClick={() => {
          setRevealed(!revealed)
        }}
      >
        {l10n.getString('password-reveal')}
      </TinyButton>
    </div>
  )
}
