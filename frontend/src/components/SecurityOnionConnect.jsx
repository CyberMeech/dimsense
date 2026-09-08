import { useEffect, useMemo, useRef, useState } from 'react'
import Spinner from './Spinner'
import { testSOConnection } from '../api'

const MAX_ROWS_LIMIT = 500000
const DEFAULT_MAX_ROWS = 50000

const INDEX_GROUPS = [
  { label: 'Zeek Logs', match: (name) => name.startsWith('logs-zeek') },
  { label: 'Suricata Alerts', match: (name) => name.startsWith('logs-suricata') },
  { label: 'Wazuh Alerts', match: (name) => name.startsWith('logs-wazuh') },
  { label: 'Other', match: () => true },
]

const FETCH_PHASES = [
  'Connecting to Security Onion...',
  'Fetching log data...',
  'Running dimensional analysis...',
]

// datetime-local wants "YYYY-MM-DDTHH:mm" in the user's local time zone.
function toDateTimeLocal(date) {
  const pad = (n) => String(n).padStart(2, '0')
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}` +
    `T${pad(date.getHours())}:${pad(date.getMinutes())}`
  )
}

// The backend interprets timestamps without an offset as UTC, so convert the
// local wall-clock value the picker gives us into an explicit UTC instant.
function toUtcIso(dateTimeLocal) {
  const d = new Date(dateTimeLocal)
  return Number.isNaN(d.getTime()) ? null : d.toISOString()
}

function groupIndices(indices) {
  const groups = INDEX_GROUPS.map((g) => ({ label: g.label, items: [] }))
  for (const name of indices) {
    const idx = INDEX_GROUPS.findIndex((g) => g.match(name))
    groups[idx].items.push(name)
  }
  return groups.filter((g) => g.items.length > 0)
}

function defaultIndex(indices) {
  return indices.find((name) => name.startsWith('logs-zeek')) ?? indices[0] ?? ''
}

const inputBase =
  'w-full rounded-lg border bg-card px-4 py-2.5 text-sm text-text-primary placeholder:text-text-secondary/60 ' +
  'focus:outline-none focus:ring-2 focus:ring-accent/40 transition-colors'

function inputClass(hasError) {
  return `${inputBase} ${hasError ? 'border-danger focus:border-danger' : 'border-border focus:border-accent'}`
}

function Field({ label, required, helper, error, htmlFor, children }) {
  return (
    <div>
      <label htmlFor={htmlFor} className="block text-sm text-text-secondary mb-1.5">
        {label}
        {required && <span className="text-danger ml-0.5">*</span>}
      </label>
      {children}
      {error ? (
        <p className="mt-1.5 text-xs text-danger">{error}</p>
      ) : helper ? (
        <p className="mt-1.5 text-xs text-text-secondary/80">{helper}</p>
      ) : null}
    </div>
  )
}

function CheckIcon() {
  return (
    <svg className="h-5 w-5 shrink-0 text-success" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path
        fillRule="evenodd"
        d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.7-9.3a1 1 0 00-1.4-1.4L9 10.6 7.7 9.3a1 1 0 00-1.4 1.4l2 2a1 1 0 001.4 0l4-4z"
        clipRule="evenodd"
      />
    </svg>
  )
}

function XIcon() {
  return (
    <svg className="h-5 w-5 shrink-0 text-danger" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path
        fillRule="evenodd"
        d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.7 7.3a1 1 0 00-1.4 1.4L8.6 10l-1.3 1.3a1 1 0 101.4 1.4L10 11.4l1.3 1.3a1 1 0 001.4-1.4L11.4 10l1.3-1.3a1 1 0 00-1.4-1.4L10 8.6 8.7 7.3z"
        clipRule="evenodd"
      />
    </svg>
  )
}

function EyeIcon({ off }) {
  return off ? (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
      <path d="M3 3l18 18M10.6 10.6a2 2 0 002.8 2.8M9.9 5.1A9.7 9.7 0 0112 5c5 0 9 4 10 7a11.4 11.4 0 01-2.6 3.7M6.2 6.2A11.6 11.6 0 002 12c1 3 5 7 10 7 1.4 0 2.7-.3 3.9-.8" />
    </svg>
  ) : (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
      <path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  )
}

/**
 * Connection form for pulling logs straight out of a Security Onion
 * Elasticsearch instance. `onFetch` receives the connection parameters plus
 * the selected index and time range and is expected to run the query and
 * navigate to the analysis page, mirroring the CSV flow. `fetchPhase` is
 * the index into FETCH_PHASES the parent is currently in (null when idle).
 */
export default function SecurityOnionConnect({ onFetch, fetchPhase, fetchError }) {
  const [host, setHost] = useState('')
  const [port, setPort] = useState('9200')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [verifySsl, setVerifySsl] = useState(false)
  const [touched, setTouched] = useState({})

  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState(null) // { success, version, indices, error }

  const [indexPattern, setIndexPattern] = useState('')
  const [fromTime, setFromTime] = useState(() => toDateTimeLocal(new Date(Date.now() - 24 * 60 * 60 * 1000)))
  const [toTime, setToTime] = useState(() => toDateTimeLocal(new Date()))
  const [maxRows, setMaxRows] = useState(String(DEFAULT_MAX_ROWS))
  const [submitAttempted, setSubmitAttempted] = useState(false)

  const connectionRef = useRef(null)

  // Any change to the connection parameters invalidates a previous test.
  useEffect(() => {
    setTestResult(null)
  }, [host, port, username, password, verifySsl])

  const portNumber = Number(port)
  const connectionErrors = {
    host: host.trim() ? null : 'Host is required',
    port:
      port !== '' && Number.isInteger(portNumber) && portNumber >= 1 && portNumber <= 65535
        ? null
        : 'Enter a port between 1 and 65535',
    username: username ? null : 'Username is required',
    password: password ? null : 'Password is required',
  }
  const connectionValid = Object.values(connectionErrors).every((e) => e === null)
  const showError = (name) => (touched[name] || submitAttempted) && connectionErrors[name]

  const maxRowsNumber = Number(maxRows)
  const fromIso = toUtcIso(fromTime)
  const toIso = toUtcIso(toTime)
  const queryErrors = {
    indexPattern: indexPattern ? null : 'Choose a log source',
    fromTime: fromIso ? null : 'Enter a valid start time',
    toTime: !toIso
      ? 'Enter a valid end time'
      : fromIso && new Date(toIso) <= new Date(fromIso)
        ? 'End time must be after the start time'
        : null,
    maxRows:
      maxRows !== '' && Number.isInteger(maxRowsNumber) && maxRowsNumber >= 1 && maxRowsNumber <= MAX_ROWS_LIMIT
        ? null
        : `Enter a number between 1 and ${MAX_ROWS_LIMIT.toLocaleString()}`,
  }
  const queryValid = Object.values(queryErrors).every((e) => e === null)

  const connected = Boolean(testResult?.success)
  const indices = useMemo(() => testResult?.indices ?? [], [testResult])
  const groupedIndices = useMemo(() => groupIndices(indices), [indices])
  const fetching = fetchPhase !== null && fetchPhase !== undefined

  async function handleTest() {
    setSubmitAttempted(true)
    if (!connectionValid) return
    setTesting(true)
    setTestResult(null)
    try {
      const result = await testSOConnection(host, portNumber, username, password, verifySsl)
      setTestResult(result)
      if (result.success) {
        setIndexPattern(defaultIndex(result.indices ?? []))
        // Scroll the newly revealed section into view on the next paint.
        setTimeout(() => connectionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 50)
      }
    } catch (err) {
      setTestResult({ success: false, version: null, indices: [], error: err.message })
    } finally {
      setTesting(false)
    }
  }

  function handleFetch() {
    if (!connected || !queryValid || fetching) return
    onFetch({
      host,
      port: portNumber,
      username,
      password,
      verifySsl,
      indexPattern,
      startTime: fromIso,
      endTime: toIso,
      maxRows: maxRowsNumber,
    })
  }

  const markTouched = (name) => () => setTouched((t) => ({ ...t, [name]: true }))

  return (
    <div className="w-full max-w-2xl mx-auto text-left">
      <div className="rounded-xl border border-border bg-card px-6 py-6 sm:px-8">
        <h2 className="text-base font-semibold text-text-primary">Connect to Security Onion</h2>
        <p className="mt-1 text-sm text-text-secondary">
          DimSense queries your Security Onion Elasticsearch instance directly and runs the same
          analysis it runs on a CSV export.
        </p>

        <div className="mt-6 grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="sm:col-span-2">
            <Field
              label="Security Onion Host"
              required
              htmlFor="so-host"
              helper="IP address or hostname of your Security Onion manager"
              error={showError('host')}
            >
              <input
                id="so-host"
                type="text"
                autoComplete="off"
                spellCheck={false}
                placeholder="192.168.1.100"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                onBlur={markTouched('host')}
                className={inputClass(showError('host'))}
              />
            </Field>
          </div>
          <Field label="Elasticsearch Port" required htmlFor="so-port" error={showError('port')}>
            <input
              id="so-port"
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={(e) => setPort(e.target.value)}
              onBlur={markTouched('port')}
              className={inputClass(showError('port'))}
            />
          </Field>
        </div>

        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
          <Field
            label="Username"
            required
            htmlFor="so-username"
            helper="Elasticsearch credentials set during Security Onion installation"
            error={showError('username')}
          >
            <input
              id="so-username"
              type="text"
              autoComplete="username"
              placeholder="admin"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              onBlur={markTouched('username')}
              className={inputClass(showError('username'))}
            />
          </Field>
          <Field
            label="Password"
            required
            htmlFor="so-password"
            helper="Elasticsearch credentials set during Security Onion installation"
            error={showError('password')}
          >
            <div className="relative">
              <input
                id="so-password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onBlur={markTouched('password')}
                className={`${inputClass(showError('password'))} pr-11`}
              />
              <button
                type="button"
                onClick={() => setShowPassword((s) => !s)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
                title={showPassword ? 'Hide password' : 'Show password'}
                className="absolute inset-y-0 right-0 px-3 flex items-center text-text-secondary hover:text-text-primary"
              >
                <EyeIcon off={showPassword} />
              </button>
            </div>
          </Field>
        </div>

        <div className="mt-4">
          <label htmlFor="so-verify-ssl" className="flex items-start gap-3 cursor-pointer select-none">
            <input
              id="so-verify-ssl"
              type="checkbox"
              checked={verifySsl}
              onChange={(e) => setVerifySsl(e.target.checked)}
              className="mt-0.5 h-4 w-4 rounded border-border bg-card accent-accent"
            />
            <span>
              <span className="block text-sm text-text-secondary">Verify SSL Certificate</span>
              <span className="block text-xs text-text-secondary/80">
                Leave unchecked for Security Onion&apos;s self-signed certificate
              </span>
            </span>
          </label>
        </div>

        <div className="mt-6 flex flex-col sm:flex-row sm:items-center gap-4">
          <button
            type="button"
            onClick={handleTest}
            disabled={testing || fetching}
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-accent px-5 py-2.5 text-sm font-semibold text-accent hover:bg-accent/10 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
          >
            {testing && <Spinner size="h-4 w-4" />}
            {testing ? 'Testing…' : 'Test Connection'}
          </button>

          {testResult && testResult.success && (
            <div className="flex items-start gap-2 text-sm" role="status">
              <CheckIcon />
              <span className="text-text-primary">
                Connected to Security Onion {testResult.version ?? ''}. {indices.length}{' '}
                {indices.length === 1 ? 'index' : 'indices'} available.
                {testResult.error && (
                  <span className="block text-xs text-warning mt-0.5">{testResult.error}</span>
                )}
              </span>
            </div>
          )}
          {testResult && !testResult.success && (
            <div className="flex items-start gap-2 text-sm" role="alert">
              <XIcon />
              <span className="text-danger break-words">{testResult.error || 'Connection failed'}</span>
            </div>
          )}
        </div>
      </div>

      {connected && (
        <div ref={connectionRef} className="mt-4 rounded-xl border border-border bg-card px-6 py-6 sm:px-8">
          <h3 className="text-base font-semibold text-text-primary">Choose what to analyze</h3>

          <div className="mt-5">
            <Field
              label="Log Source"
              required
              htmlFor="so-index"
              error={submitAttempted && queryErrors.indexPattern}
              helper={indices.length === 0 ? 'No indices were returned for this account' : undefined}
            >
              <select
                id="so-index"
                value={indexPattern}
                onChange={(e) => setIndexPattern(e.target.value)}
                disabled={indices.length === 0}
                className={`${inputClass(submitAttempted && queryErrors.indexPattern)} disabled:opacity-60`}
              >
                {indices.length === 0 && <option value="">No indices available</option>}
                {groupedIndices.map((group) => (
                  <optgroup key={group.label} label={group.label}>
                    {group.items.map((name) => (
                      <option key={name} value={name}>
                        {name}
                      </option>
                    ))}
                  </optgroup>
                ))}
              </select>
            </Field>
          </div>

          <div className="mt-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Field label="From" required htmlFor="so-from" error={queryErrors.fromTime}>
                <input
                  id="so-from"
                  type="datetime-local"
                  value={fromTime}
                  onChange={(e) => setFromTime(e.target.value)}
                  className={`${inputClass(queryErrors.fromTime)} [color-scheme:dark]`}
                />
              </Field>
              <Field label="To" required htmlFor="so-to" error={queryErrors.toTime}>
                <input
                  id="so-to"
                  type="datetime-local"
                  value={toTime}
                  onChange={(e) => setToTime(e.target.value)}
                  className={`${inputClass(queryErrors.toTime)} [color-scheme:dark]`}
                />
              </Field>
            </div>
            <p className="mt-1.5 text-xs text-text-secondary/80">Select the time window to analyze</p>
          </div>

          <div className="mt-4 sm:max-w-xs">
            <Field
              label="Maximum rows to fetch"
              required
              htmlFor="so-max-rows"
              helper="Larger datasets take longer to analyze. Start with 50,000."
              error={queryErrors.maxRows}
            >
              <input
                id="so-max-rows"
                type="number"
                min={1}
                max={MAX_ROWS_LIMIT}
                step={1000}
                value={maxRows}
                onChange={(e) => setMaxRows(e.target.value)}
                className={inputClass(queryErrors.maxRows)}
              />
            </Field>
          </div>

          <div className="mt-6 flex flex-col sm:flex-row sm:items-center gap-4">
            <button
              type="button"
              onClick={handleFetch}
              disabled={!queryValid || fetching}
              className="inline-flex items-center justify-center gap-2 rounded-lg bg-accent px-6 py-3 text-sm font-semibold text-white hover:bg-accent/90 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
            >
              {fetching && <Spinner size="h-4 w-4" />}
              {fetching ? FETCH_PHASES[fetchPhase] : 'Fetch and Analyze'}
            </button>
            {fetching && (
              <span className="text-xs text-text-secondary" aria-live="polite">
                Step {fetchPhase + 1} of {FETCH_PHASES.length}
              </span>
            )}
          </div>

          {fetchError && (
            <div className="mt-4 flex items-start gap-2 text-sm" role="alert">
              <XIcon />
              <span className="text-danger break-words">{fetchError}</span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
