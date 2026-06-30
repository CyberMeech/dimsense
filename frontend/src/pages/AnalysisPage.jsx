import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import FieldSelectionSection from '../components/FieldSelectionSection'
import AnomalyCharts from '../components/AnomalyCharts'
import AnomalyAlerts from '../components/AnomalyAlerts'

export default function AnalysisPage() {
  const location = useLocation()
  const [result, setResult] = useState(null)

  const navState = location.state

  if (!navState) {
    return (
      <div className="max-w-2xl mx-auto px-6 py-20 text-center">
        <h1 className="text-xl font-bold text-text-primary">
          No analysis data found
        </h1>
        <p className="mt-2 text-text-secondary">
          Upload a CSV from the home page to start an analysis.
        </p>
        <Link
          to="/"
          className="mt-6 inline-flex items-center rounded-lg bg-accent px-5 py-2.5 text-sm font-semibold text-white hover:bg-accent/90"
        >
          Go to Home
        </Link>
      </div>
    )
  }

  const { sessionId, fields } = navState

  return (
    <div>
      <FieldSelectionSection
        sessionId={sessionId}
        fields={fields}
        onConfirmed={setResult}
      />

      {result && (
        <>
          <AnomalyCharts windows={result.data.windows} fields={result.confirmedFields} />
          <AnomalyAlerts flaggedWindows={result.data.flagged_windows} />
        </>
      )}
    </div>
  )
}
