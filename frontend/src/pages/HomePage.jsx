import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import UploadDropzone from '../components/UploadDropzone'
import SecurityOnionConnect from '../components/SecurityOnionConnect'
import HowItWorks from '../components/HowItWorks'
import ErrorBanner from '../components/ErrorBanner'
import { uploadCsv, analyzeCsv, querySOData } from '../api'

const TABS = [
  { id: 'csv', label: 'Upload CSV' },
  { id: 'so', label: 'Connect to Security Onion' },
]

// How long the "Connecting..." phase is shown before switching to
// "Fetching log data..." while the single /so/query request is in flight.
const CONNECTING_PHASE_MS = 1200

export default function HomePage() {
  const [tab, setTab] = useState('csv')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [soPhase, setSoPhase] = useState(null) // null | 0 | 1 | 2
  const [soError, setSoError] = useState(null)
  const navigate = useNavigate()

  function goToAnalysis(sessionId, analysis) {
    navigate('/analysis', {
      state: {
        sessionId,
        totalRecords: analysis.total_records,
        totalFields: analysis.total_fields,
        fields: analysis.fields,
      },
    })
  }

  async function handleAnalyze(file) {
    setLoading(true)
    setError(null)
    try {
      const upload = await uploadCsv(file)
      const analysis = await analyzeCsv(upload.session_id)
      goToAnalysis(upload.session_id, analysis)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleSecurityOnionFetch(params) {
    setSoError(null)
    setSoPhase(0)
    const phaseTimer = setTimeout(() => setSoPhase((p) => (p === 0 ? 1 : p)), CONNECTING_PHASE_MS)
    try {
      const query = await querySOData(
        params.host,
        params.port,
        params.username,
        params.password,
        params.verifySsl,
        params.indexPattern,
        params.startTime,
        params.endTime,
        params.maxRows,
      )
      clearTimeout(phaseTimer)
      setSoPhase(2)
      const analysis = await analyzeCsv(query.session_id)
      goToAnalysis(query.session_id, analysis)
    } catch (err) {
      clearTimeout(phaseTimer)
      setSoError(err.message)
    } finally {
      setSoPhase(null)
    }
  }

  return (
    <div>
      <section className="max-w-4xl mx-auto px-6 pt-20 pb-16 text-center">
        <h1 className="text-4xl sm:text-5xl font-extrabold text-text-primary tracking-tight leading-tight">
          Enterprise Anomaly Detection From Your Existing EDR Data
        </h1>
        <p className="mt-6 text-lg text-text-secondary max-w-2xl mx-auto leading-relaxed">
          DimSense applies MIT/USAF research to automatically identify the most
          important fields in your logs and surface coordinated behavioral
          anomalies that rule-based systems miss.
        </p>

        <div className="mt-10">
          <div className="w-full max-w-2xl mx-auto mb-6">
            <div role="tablist" aria-label="Data source" className="flex border-b border-border">
              {TABS.map((t) => {
                const active = tab === t.id
                return (
                  <button
                    key={t.id}
                    id={`tab-${t.id}`}
                    role="tab"
                    type="button"
                    aria-selected={active}
                    aria-controls={`panel-${t.id}`}
                    onClick={() => setTab(t.id)}
                    className={`-mb-px px-4 py-3 text-sm font-medium border-b-2 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 rounded-t ${
                      active
                        ? 'border-accent text-white'
                        : 'border-transparent text-text-secondary hover:text-text-primary'
                    }`}
                  >
                    {t.label}
                  </button>
                )
              })}
            </div>
          </div>

          {tab === 'csv' && (
            <div id="panel-csv" role="tabpanel" aria-labelledby="tab-csv">
              <UploadDropzone onAnalyze={handleAnalyze} loading={loading} />
              {error && (
                <div className="mt-6 max-w-2xl mx-auto text-left">
                  <ErrorBanner message={error} />
                </div>
              )}
            </div>
          )}

          {tab === 'so' && (
            <div id="panel-so" role="tabpanel" aria-labelledby="tab-so">
              <SecurityOnionConnect
                onFetch={handleSecurityOnionFetch}
                fetchPhase={soPhase}
                fetchError={soError}
              />
            </div>
          )}
        </div>
      </section>

      <HowItWorks />
    </div>
  )
}
