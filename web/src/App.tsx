import { Localized } from '@fluent/react'
import { KickerTag } from './components/KickerTag'
import { StatusBar } from './components/StatusBar'

const HSTAT_IDS = [
  'hstat-services-active-label',
  'hstat-pending-commit-label',
  'hstat-cert-expiry-label',
  'hstat-update-state-label',
  'hstat-uptime-label',
] as const

function App() {
  return (
    <>
      <StatusBar />
      <section className="wrap" style={{ paddingTop: 48, paddingBottom: 48 }}>
        <div className="kicker" style={{ marginBottom: 24 }}>
          <KickerTag variant="blue">
            <Localized id="kicker-model">
              <span>dt-7</span>
            </Localized>
          </KickerTag>
          <KickerTag>
            <Localized id="kicker-class">
              <span>config console</span>
            </Localized>
          </KickerTag>
          <KickerTag>
            <Localized id="kicker-rev">
              <span>rev. e</span>
            </Localized>
          </KickerTag>
        </div>
        <h1 className="designation">
          <Localized id="app-designation">
            <span>detent.</span>
          </Localized>
        </h1>
        <p className="subline" style={{ marginBottom: 24 }}>
          <Localized id="app-lede">
            <span>the busybox of config files.</span>
          </Localized>
        </p>
        <div className="hstats">
          {HSTAT_IDS.map((id) => (
            <div className="cell" key={id}>
              <div className="v read">--</div>
              <div className="k">
                <Localized id={id}>
                  <span>{id}</span>
                </Localized>
              </div>
            </div>
          ))}
        </div>
      </section>
    </>
  )
}

export default App
