
import { useEffect, useState } from 'react'
import './App.css'

const menu = [
  'Overview',
  'Network Monitor',
  'AI Threat Detection',
  'Autonomous Defence',
  'Digital Twin',
  'AIORI Traceback',
  'Activity Logs',
]

const endpoints = {
  summary: '/api/dashboard/summary',
  detections: '/api/dashboard/detections?limit=500',
  defences: '/api/dashboard/defences?limit=500',
  investigations: '/api/investigations',
  twin: '/api/twin/validations',
}

function asItems(data) {
  if (Array.isArray(data)) return data
  return Array.isArray(data?.items) ? data.items : []
}

function number(value) {
  return typeof value === 'number' ? value : '—'
}

function date(value) {
  if (!value) return '—'
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString()
}

function source(item) {
  return item.source_ip || item.src_ip || item.src || 'Unavailable'
}

function attack(item) {
  return item.attack_type || item.predicted_label || item.label || item.message || 'Recorded event'
}

function severity(item) {
  const value = String(item.severity || item.risk_level || '').toUpperCase()
  if (value.includes('CRITICAL')) return 'CRITICAL'
  if (value.includes('HIGH')) return 'HIGH'
  if (value.includes('MEDIUM')) return 'MEDIUM'
  if (value.includes('LOW')) return 'LOW'
  return 'RECORDED'
}

function Panel({ title, children }) {
  return (
    <section className="panel">
      <h3>{title}</h3>
      {children}
    </section>
  )
}

function RecordList({ items, emptyMessage = 'No records returned by the backend.' }) {
  if (!items.length) return <p className="muted">{emptyMessage}</p>

  return (
    <div className="events">
      {items.map((item, index) => (
        <div className="event-row" key={item.id || item.validation_id || item.timestamp || index}>
          <span className="event-tag warning">{severity(item)}</span>
          <span>
            <strong>{attack(item)}</strong>
            <p>Source: {source(item)}</p>
            {item.action && <p>Action: {item.action}</p>}
            {item.approved !== undefined && (
              <p>Approved: {item.approved ? 'Yes' : 'No'}</p>
            )}
            {item.executed !== undefined && (
              <p>Executed: {item.executed ? 'Yes' : 'No'}</p>
            )}
            {item.mode && <p>Mode: {item.mode}</p>}
            {item.reason && <p>{item.reason}</p>}
            {item.scenario && <p>Scenario: {item.scenario}</p>}
            {item.result_status && <p>Status: {item.result_status}</p>}
          </span>
          <span>{date(item.timestamp)}</span>
        </div>
      ))}
    </div>
  )
}

function App() {
  const [activeTab, setActiveTab] = useState('Overview')
  const [monitoringSummary, setMonitoringSummary] = useState(null)
  const [monitoringFlows, setMonitoringFlows] = useState([])
  const [monitoringError, setMonitoringError] = useState('')

  const [summary, setSummary] = useState(null)
  const [detections, setDetections] = useState([])
  const [defences, setDefences] = useState([])
  const [investigations, setInvestigations] = useState([])
  const [validations, setValidations] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [traceIp, setTraceIp] = useState('')
  const [traceResult, setTraceResult] = useState(null)
  const [traceError, setTraceError] = useState('')
  const [traceLoading, setTraceLoading] = useState(false)

  useEffect(() => {
    let mounted = true

    async function loadDashboard() {
      try {
        const [summaryResponse, flowsResponse] = await Promise.all([
          fetch('/api/monitoring/summary'),
          fetch('/api/monitoring/flows?limit=20'),
        ])
        if (!summaryResponse.ok || !flowsResponse.ok) {
          throw new Error('Monitoring API request failed')
        }
        const summaryData = await summaryResponse.json()
        const flowsData = await flowsResponse.json()
        setMonitoringSummary(summaryData)
        setMonitoringFlows(flowsData.items || [])
        setMonitoringError('')
      } catch (error) {
        setMonitoringError(error.message || 'Monitoring data unavailable')
      }

      try {
        const results = await Promise.all(
          Object.entries(endpoints).map(async ([key, url]) => {
            const response = await fetch(url)
            if (!response.ok) throw new Error(`${key} endpoint returned HTTP ${response.status}`)
            return [key, await response.json()]
          }),
        )

        if (!mounted) return
        const data = Object.fromEntries(results)
        setSummary(data.summary)
        setDetections(
          asItems(data.detections).sort((a, b) => {
            const actionPriority =
              Number(Boolean(b.action_required)) -
              Number(Boolean(a.action_required))
            if (actionPriority !== 0) return actionPriority
            return new Date(b.timestamp || 0) - new Date(a.timestamp || 0)
          }),
        )
        setDefences(
          asItems(data.defences).sort((a, b) => {
            const priority =
              Number(b.action === 'BLOCK_IP') -
              Number(a.action === 'BLOCK_IP')
            if (priority !== 0) return priority
            return new Date(b.timestamp || 0) - new Date(a.timestamp || 0)
          }),
        )
        setInvestigations(asItems(data.investigations))
        setValidations(asItems(data.twin))
        setError('')
      } catch (err) {
        if (mounted) setError(err.message || 'Unable to load backend data.')
      } finally {
        if (mounted) setLoading(false)
      }
    }

    loadDashboard()
    const timer = setInterval(loadDashboard, 10000)

    return () => {
      mounted = false
      clearInterval(timer)
    }
  }, [])

  async function investigateSource(event) {
    event.preventDefault()
    const ip = traceIp.trim()
    if (!ip) return

    setTraceLoading(true)
    setTraceError('')
    setTraceResult(null)

    try {
      const response = await fetch(`/api/traceback/${encodeURIComponent(ip)}`)
      const data = await response.json()
      if (!response.ok) throw new Error(data.detail || `Traceback returned HTTP ${response.status}`)
      setTraceResult(data)
    } catch (err) {
      setTraceError(err.message || 'Traceback request failed.')
    } finally {
      setTraceLoading(false)
    }
  }

  const recentEvents = [...detections, ...defences]
    .sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0))
    .slice(0, 50)

const activityBuckets = Array.from({ length: 6 }, (_, index) => {
  const start = new Date()
  start.setMinutes(0, 0, 0)
  start.setHours(start.getHours() - (5 - index))

  const end = new Date(start)
  end.setHours(end.getHours() + 1)

  const count = detections.filter((item) => {
    const timestamp = new Date(item.timestamp).getTime()
    return Number.isFinite(timestamp) &&
      timestamp >= start.getTime() &&
      timestamp < end.getTime()
  }).length

  return {
    label: start.toLocaleTimeString([], { hour: '2-digit' }),
    count,
  }
})

const maxActivity = Math.max(1, ...activityBuckets.map((item) => item.count))

  function renderContent() {
    switch (activeTab) {
      case 'Overview':
        return (
          <>
            <section className="welcome">
              <div>
                <p className="eyebrow">AUTONOMOUS CYBER DEFENCE WITH DIGITAL TWIN</p>
                <h2>Network security at a glance.</h2>
                <p>Review recorded detections, defence activity, investigations, and Digital Twin validation results.</p>
              </div>
              <div className="shield">🛡️</div>
            </section>

            <section className="stats">
              {[
                ['Detection Log Records', summary?.detection_log_records, 'Records reported by the API'],
                ['Defence Log Records', summary?.defence_log_records, 'Recorded defence actions'],
                ['Investigations', summary?.investigations, 'Recorded investigations'],
                ['Twin Validations', summary?.twin_validation_records, `Simulations executed: ${number(summary?.twin_simulations_executed)}`],
              ].map(([label, value, description]) => (
                <article className="stat-card" key={label}>
                  <p>{label}</p>
                  <h2>{loading ? '…' : number(value)}</h2>
                  <span>{description}</span>
                </article>
              ))}
            </section>

            <section className="content-grid">


<Panel title="Recorded Detection Activity">
  <p className="muted">
    Backend detection records grouped by hour over the last six hours.
    This represents recorded detections, not live packet volume.
  </p>

  <div className="chart">
    {activityBuckets.map((item) => (
      <div
        className="bar"
        key={item.label}
        title={`${item.label}: ${item.count} detections`}
        style={{
          height: `${Math.max(4, (item.count / maxActivity) * 100)}%`,
        }}
      />
    ))}
  </div>

  <div className="chart-labels">
    {activityBuckets.map((item) => (
      <span key={item.label}>{item.label}</span>
    ))}
  </div>

  <p className="muted">
    Total records currently loaded: {detections.length}
  </p>
</Panel>

              <Panel title="Core Modules">
                {[
                  ['01', 'Network Monitoring'],
                  ['02', 'AI Threat Detection'],
                  ['03', 'Autonomous Defence'],
                  ['04', 'AIORI + Twin Validation'],
                  ['05', 'Dashboard & Data'],
                ].map(([n, label]) => (
                  <div className="module-row" key={n}>
                    <span className="module-number">{n}</span>
                    <span>{label}</span>
                    <span className="module-arrow">›</span>
                  </div>
                ))}
              </Panel>
            </section>

            <Panel title="Recent Detection Records">
              <p className="muted">Loaded from the backend and refreshed every 10 seconds.</p>
              <RecordList items={detections.slice(0, 10)} />
            </Panel>

            <Panel title="Backend Safety Status">
              <p>Firewall commands reported as executed: <strong>{number(summary?.firewall_commands_executed)}</strong></p>
              <p className="muted">Firewall execution remains governed by the backend dry-run design.</p>
            </Panel>
          </>
        )

      case 'Network Monitor':
        return (
          <div className="page-content">
            <section className="stats-grid">
              <div className="stat-card">
                <span>Buffered Flows</span>
                <strong>{monitoringSummary?.flows_buffered ?? 0}</strong>
              </div>
              <div className="stat-card">
                <span>Packets Observed</span>
                <strong>{monitoringSummary?.packets_observed ?? 0}</strong>
              </div>
              <div className="stat-card">
                <span>Bytes Observed</span>
                <strong>{monitoringSummary?.bytes_observed ?? 0}</strong>
              </div>
              <div className="stat-card">
                <span>Protocols</span>
                <strong>{monitoringSummary?.protocols?.join(', ') || '—'}</strong>
              </div>
            </section>

            <section className="panel">
              <h2>Captured Network Flows</h2>
              {monitoringError && <p role="alert">{monitoringError}</p>}
              <p>
                Collector status: {monitoringSummary?.collector_running ? 'Running' : 'Stopped / bounded capture'}
              </p>
              {monitoringFlows.length === 0 ? (
                <p>No flow records available. Run the packet capture script to collect a bounded sample.</p>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Protocol</th>
                        <th>Packets</th>
                        <th>Bytes</th>
                        <th>Duration (s)</th>
                      </tr>
                    </thead>
                    <tbody>
                      {monitoringFlows.map((flow, index) => (
                        <tr key={`${flow.source_ip}-${flow.destination_ip}-${flow.observed_at || index}`}>
                          <td>{flow.source_ip}:{flow.source_port}</td>
                          <td>{flow.destination_ip}:{flow.destination_port}</td>
                          <td>{flow.protocol}</td>
                          <td>{Number(flow.total_fwd_packets || 0) + Number(flow.total_backward_packets || 0)}</td>
                          <td>{Number(flow.total_fwd_bytes || 0) + Number(flow.total_backward_bytes || 0)}</td>
                          <td>{Number(flow.flow_duration_sec || 0).toFixed(4)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <p className="muted">
                {monitoringSummary?.message || 'Counts are based on exported flow records.'}
              </p>
            </section>
          </div>
        )

      case 'AI Threat Detection':
        return (
          <Panel title="AI Detection Records">
            <p className="muted">
              Backend detection records. These results are not a claim that a new attack is occurring now.
            </p>
            {!detections.length ? (
              <p className="muted">No detection records returned by the backend.</p>
            ) : (
              <div className="detection-records">
                {detections.map((item, index) => {
                  const confidence =
                    typeof item.confidence_percent === 'number'
                      ? item.confidence_percent
                      : typeof item.confidence === 'number'
                        ? (item.confidence <= 1
                            ? item.confidence * 100
                            : item.confidence)
                        : null

                  return (
                    <article
                      className="detection-card"
                      key={item.id || item.timestamp || `${source(item)}-${index}`}
                    >
                      <div className="detection-card-heading">
                        <div>
                          <h4>{attack(item)}</h4>
                          <p className="muted">Source IP: {source(item)}</p>
                        </div>
                        <span className="event-tag warning">{severity(item)}</span>
                      </div>

                      <div className="detection-fields">
                        <div className="detection-field">
                          <span>Confidence</span>
                          <strong>{confidence === null ? '—' : `${confidence.toFixed(1)}%`}</strong>
                        </div>
                        <div className="detection-field">
                          <span>Severity</span>
                          <strong>{severity(item)}</strong>
                        </div>
                        <div className="detection-field">
                          <span>Random Forest prediction</span>
                          <strong>{item.rf_prediction || 'Unavailable'}</strong>
                        </div>
                        <div className="detection-field">
                          <span>Anomaly detected</span>
                          <strong>
                            {item.anomaly === true
                              ? 'Yes'
                              : item.anomaly === false
                                ? 'No'
                                : 'Unavailable'}
                          </strong>
                        </div>
                        <div className="detection-field">
                          <span>Detection source</span>
                          <strong>{item.detection_source || 'Unavailable'}</strong>
                        </div>
                        <div className="detection-field">
                          <span>Timestamp</span>
                          <strong>{date(item.timestamp)}</strong>
                        </div>
                      </div>
                    </article>
                  )
                })}
              </div>
            )}
          </Panel>
        )

      case 'Autonomous Defence':
        return (
          <>
            <section className="stats">
              <article className="stat-card"><p>Defence Records</p><h2>{defences.length}</h2><span>Returned by the API</span></article>
              <article className="stat-card"><p>Executed Commands</p><h2>{number(summary?.firewall_commands_executed)}</h2><span>Reported by backend</span></article>
            </section>
            <Panel title="Defence Actions">
              <p className="muted">The current backend uses dry-run mode. Displaying an action does not mean a firewall rule was applied.</p>
              <RecordList items={defences} />
            </Panel>
          </>
        )

      case 'Digital Twin':
        return (
          <>
            <section className="stats">
              <article className="stat-card"><p>Validation Records</p><h2>{validations.length}</h2><span>Stored validation results</span></article>
              <article className="stat-card"><p>Simulations Executed</p><h2>{number(summary?.twin_simulations_executed)}</h2><span>Reported by backend</span></article>
            </section>
            <Panel title="Digital Twin Validations">
              <p className="muted">Validation records are shown separately from simulations actually executed.</p>
              <RecordList items={validations} />
            </Panel>
          </>
        )

      case 'AIORI Traceback':
        return (
          <>
            <Panel title="Traceback Investigation">
              <p className="muted">Enter a source IP to query the existing traceback endpoint.</p>
              <form className="trace-form" onSubmit={investigateSource}>
                <input value={traceIp} onChange={(event) => setTraceIp(event.target.value)} placeholder="Example: 192.168.1.2" aria-label="Source IP address" />
                <button type="submit" disabled={traceLoading}>{traceLoading ? 'Searching…' : 'Investigate IP'}</button>
              </form>
              {traceError && <p role="alert">{traceError}</p>}
              {traceResult && <pre className="trace-result">{JSON.stringify(traceResult, null, 2)}</pre>}
            </Panel>
            <Panel title="Investigation Records">
              <RecordList items={investigations} emptyMessage="No investigation records have been saved." />
            </Panel>
          </>
        )

      case 'Activity Logs':
        return (
          <Panel title="Recent Security Activity">
            <p className="muted">Combined view of detection and defence records returned by the backend.</p>
            <RecordList items={recentEvents} />
          </Panel>
        )

      default:
        return <Panel title="Section unavailable"><p>Select a module from the sidebar.</p></Panel>
    }
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <h2>🛡 CyberDefence</h2>
        <p className="subtitle">AUTONOMOUS SECURITY</p>
        <nav>
          {menu.map((item) => (
            <button key={item} className={activeTab === item ? 'nav-item active' : 'nav-item'} onClick={() => setActiveTab(item)}>
              {item}
            </button>
          ))}
        </nav>
        <div className="sidebar-status">
          <span className="status-dot" />
          {summary ? 'Backend connected' : 'Connecting to backend'}
          <p>{loading ? 'Loading data…' : error ? 'Connection issue' : 'API data enabled'}</p>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <p className="eyebrow">SECURITY OPERATIONS CENTER</p>
            <h1>{activeTab}</h1>
          </div>
          <span className="preview-badge">{error ? 'CONNECTION ISSUE' : summary ? 'BACKEND CONNECTED' : 'CONNECTING'}</span>
        </header>

        {error && <section className="panel" role="alert"><p>{error}</p></section>}
        {renderContent()}

        <footer>AUTONOMOUS CYBER DEFENCE · BACKEND API INTEGRATION</footer>
      </main>
    </div>
  )
}

export default App
