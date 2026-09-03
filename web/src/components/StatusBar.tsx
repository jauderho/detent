import { Localized } from '@fluent/react'
import { useEffect, useState } from 'react'
import { Led } from './Led'
import { ThemeRocker } from './ThemeRocker'

function pad2(n: number): string {
  return n < 10 ? `0${n}` : `${n}`
}

function formatUtc(d: Date): string {
  return `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`
}

function useUtcClock(): string {
  const [now, setNow] = useState(() => formatUtc(new Date()))

  useEffect(() => {
    const id = window.setInterval(() => {
      setNow(formatUtc(new Date()))
    }, 1000)
    return () => window.clearInterval(id)
  }, [])

  return now
}

export function StatusBar() {
  const clock = useUtcClock()

  return (
    <header className="status">
      <div className="seg brand">
        <span className="mark" aria-hidden="true" />
        <Localized id="status-brand">
          <span>detent</span>
        </Localized>
      </div>
      <div className="seg">
        <Led variant="on" />
        <span className="lbl">
          <Localized id="status-online">
            <span>system online</span>
          </Localized>
        </span>
      </div>
      <div className="seg" style={{ marginLeft: 'auto' }}>
        <span className="lbl dim">
          <Localized id="status-clock-label">
            <span>utc</span>
          </Localized>
        </span>
        <span className="clock read tabular-nums">{clock}</span>
      </div>
      <div className="seg">
        <ThemeRocker />
      </div>
    </header>
  )
}
