import { useMemo, useState } from 'react'
import StatsBar from './StatsBar'
import FieldTable from './FieldTable'
import ErrorBanner from './ErrorBanner'
import Spinner from './Spinner'
import { confirmFields } from '../api'

export default function FieldSelectionSection({ sessionId, fields, onConfirmed }) {
  const [selected, setSelected] = useState(() => {
    const initial = {}
    for (const field of fields) {
      initial[field.field_name] = field.algorithm_recommended
    }
    return initial
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const recommendedCount = useMemo(
    () => fields.filter((f) => f.algorithm_recommended).length,
    [fields],
  )
  const selectedCount = useMemo(
    () => Object.values(selected).filter(Boolean).length,
    [selected],
  )

  function toggleField(fieldName) {
    setSelected((prev) => ({ ...prev, [fieldName]: !prev[fieldName] }))
  }

  async function handleConfirm() {
    const selectedFields = fields
      .filter((f) => selected[f.field_name])
      .map((f) => f.field_name)

    setLoading(true)
    setError(null)
    try {
      const data = await confirmFields(sessionId, selectedFields)
      onConfirmed({ confirmedFields: selectedFields, data })
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="max-w-6xl mx-auto px-6 py-12">
      <h1 className="text-2xl font-bold text-text-primary">Field Selection Review</h1>
      <p className="mt-2 text-text-secondary max-w-2xl">
        The algorithm has pre-selected fields with the strongest analytical
        signal. You can override any selection.
      </p>

      <div className="mt-6">
        <StatsBar
          totalFields={fields.length}
          recommendedCount={recommendedCount}
          selectedCount={selectedCount}
        />
      </div>

      <div className="mt-4 space-y-2">
        {selectedCount < 5 && (
          <div className="rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm text-warning">
            Fewer than 5 fields selected — anomaly detection may have limited
            signal to work with.
          </div>
        )}
        {selectedCount > 20 && (
          <div className="rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm text-warning">
            More than 20 fields selected — consider narrowing your selection
            for clearer results.
          </div>
        )}
      </div>

      <div className="mt-6">
        <FieldTable fields={fields} selected={selected} onToggle={toggleField} />
      </div>

      {error && (
        <div className="mt-6">
          <ErrorBanner message={error} />
        </div>
      )}

      <div className="mt-8 flex justify-center">
        <button
          type="button"
          disabled={loading || selectedCount === 0}
          onClick={handleConfirm}
          className="inline-flex items-center gap-2 rounded-lg bg-accent px-6 py-3 text-sm font-semibold text-white hover:bg-accent/90 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
        >
          {loading && <Spinner size="h-4 w-4" />}
          {loading ? 'Running…' : 'Run Anomaly Detection'}
        </button>
      </div>
    </section>
  )
}
