function formatTimestamp(iso) {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function getSeverityTier(score) {
  if (score >= 17) {
    return {
      label: 'Critical confidence',
      badgeClass: 'bg-danger/15 text-danger',
      bannerClass: 'border-danger/40 bg-danger/10',
    }
  }
  if (score >= 12) {
    return {
      label: 'High confidence',
      badgeClass: 'bg-orange-500/15 text-orange-400',
      bannerClass: 'border-orange-500/40 bg-orange-500/10',
    }
  }
  return {
    label: 'Low-Medium confidence',
    badgeClass: 'bg-warning/15 text-warning',
    bannerClass: 'border-warning/40 bg-warning/10',
  }
}

const HIGH_CONFIDENCE_CALLOUT =
  'High confidence anomaly — multiple independent dimensions confirmed this pattern. Do not dismiss without investigation.'

const ACTION_REQUIRED_TEXT =
  "Verify with your team that this activity was expected, scheduled, or authorized. If no known activity explains this pattern — initiate your incident response process per your organization's SOPs."

function contributingFields(fieldStats) {
  return fieldStats.filter((f) => f.n_max_anomalous || f.n_unique_anomalous)
}

// The backend's anomaly_score is event-rate-anomalous (0 or 1) plus the sum of
// n_max_anomalous/n_unique_anomalous across every field. Subtracting the field
// total recovers whether the event rate itself spiked, without re-parsing prose.
function classifyPattern(window) {
  const contributors = contributingFields(window.field_stats)
  const fieldContribution = window.field_stats.reduce(
    (sum, f) => sum + (f.n_max_anomalous ? 1 : 0) + (f.n_unique_anomalous ? 1 : 0),
    0,
  )
  const eventRateSpiked = window.anomaly_score - fieldContribution >= 1
  const anyConcentration = contributors.some((f) => f.n_max_anomalous)
  const anyDiversity = contributors.some((f) => f.n_unique_anomalous)

  if (eventRateSpiked && anyConcentration && anyDiversity) {
    return 'Coordinated activity detected across multiple dimensions simultaneously.'
  }
  if (anyConcentration && !anyDiversity) {
    return 'Concentrated activity detected — a small number of entities dominated this window.'
  }
  if (anyDiversity && !anyConcentration) {
    return 'Broad participation detected — more distinct entities were active than normal.'
  }
  if (eventRateSpiked && !anyConcentration && !anyDiversity) {
    return 'Volume spike detected without a distributional shift.'
  }
  if (anyConcentration && !eventRateSpiked) {
    return 'Quiet concentration detected — activity consolidated around fewer entities than baseline.'
  }
  return 'Multiple anomalous dimensional metrics detected in this window.'
}

function SectionLabel({ children }) {
  return (
    <p className="text-xs font-semibold text-text-secondary uppercase tracking-wide mb-1">
      {children}
    </p>
  )
}

function FlaggedWindowCard({ window }) {
  const contributors = contributingFields(window.field_stats)
  const tier = getSeverityTier(window.anomaly_score)

  return (
    <div className="rounded-xl border border-border bg-card p-6 space-y-5">
      <p className="text-sm text-text-secondary">Window {window.window_index}</p>

      <div className={`rounded-lg border p-4 ${tier.bannerClass}`}>
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <span
            className={`inline-flex items-center rounded-full px-3 py-1 text-sm font-bold ${tier.badgeClass}`}
          >
            Score {window.anomaly_score}
          </span>
          <span className="text-sm font-semibold text-text-primary">{tier.label}</span>
        </div>
        {window.anomaly_score >= 12 && (
          <p className="mt-3 text-sm font-bold text-text-primary leading-relaxed">
            {HIGH_CONFIDENCE_CALLOUT}
          </p>
        )}
      </div>

      {contributors.length > 0 && (
        <div>
          <SectionLabel>Contributing fields</SectionLabel>
          <ul className="mt-2 flex flex-wrap gap-2">
            {contributors.map((f) => {
              const metrics = []
              if (f.n_max_anomalous) metrics.push('concentration')
              if (f.n_unique_anomalous) metrics.push('diversity')
              return (
                <li
                  key={f.field_name}
                  className="rounded-md border border-border bg-bg px-2.5 py-1 text-xs text-text-primary"
                >
                  <span className="font-medium">{f.field_name}</span>
                  <span className="text-text-secondary"> &middot; {metrics.join(' & ')}</span>
                </li>
              )
            })}
          </ul>
        </div>
      )}

      <div>
        <SectionLabel>What happened</SectionLabel>
        <p className="text-sm text-text-primary leading-relaxed">{classifyPattern(window)}</p>
      </div>

      <div>
        <SectionLabel>Findings summary</SectionLabel>
        <p className="text-sm text-text-primary leading-relaxed border-l-4 border-l-accent bg-white/5 rounded-r-lg px-4 py-3">
          {window.interpretation}
        </p>
      </div>

      <div>
        <SectionLabel>Timeline</SectionLabel>
        <p className="text-sm text-text-primary">
          {formatTimestamp(window.window_start)} &rarr; {formatTimestamp(window.window_end)}
        </p>
      </div>

      <div className="rounded-lg border border-warning/40 bg-warning/10 p-4">
        <p className="text-sm font-bold uppercase tracking-wide text-warning mb-1">
          Action required
        </p>
        <p className="text-sm text-text-primary leading-relaxed">{ACTION_REQUIRED_TEXT}</p>
      </div>
    </div>
  )
}

export default function AnomalyAlerts({ flaggedWindows }) {
  return (
    <section className="max-w-6xl mx-auto px-6 py-12">
      <h2 className="text-2xl font-bold text-text-primary">Flagged Windows</h2>
      <p className="mt-2 text-text-secondary max-w-2xl">
        Windows where multiple dimensions spiked simultaneously — the
        coordinated pattern the paper identifies as highest confidence.
      </p>

      <div className="mt-6 space-y-4">
        {flaggedWindows.length === 0 ? (
          <div className="rounded-xl border border-border bg-card p-6 text-text-secondary">
            No anomalies detected above threshold. Your baseline behavior
            appears stable across this dataset.
          </div>
        ) : (
          flaggedWindows.map((window) => (
            <FlaggedWindowCard key={window.window_index} window={window} />
          ))
        )}
      </div>
    </section>
  )
}
