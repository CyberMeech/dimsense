import { Link } from 'react-router-dom'

const HOW_IT_WORKS = [
  {
    title: 'Upload Your EDR Export',
    description:
      'Export a CSV from CrowdStrike, SentinelOne, or any EDR platform. DimSense accepts any structured log export.',
  },
  {
    title: 'Algorithm Identifies Signal Fields',
    description:
      'Your EDR logs may have 250+ fields. Most are noise at enterprise scale. DimSense automatically scores every field and identifies the small set that actually carries behavioral signal — no manual configuration required.',
  },
  {
    title: 'See Coordinated Anomalies',
    description:
      'Rather than alerting on individual spikes, DimSense detects when multiple independent dimensions shift simultaneously. That coordinated pattern is what separates real incidents from noise.',
  },
]

const PRIVACY_POINTS = [
  {
    text: 'No internet required — the desktop app runs entirely offline. Zero outbound connections.',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 20h.01" />
        <path d="M8.5 16.5a5 5 0 0 1 7 0" />
        <path d="M5 12.5a10 10 0 0 1 14 0" />
        <path d="M2 8.5a15 15 0 0 1 20 0" />
        <line x1="2" y1="2" x2="22" y2="22" />
      </svg>
    ),
  },
  {
    text: 'Nothing is stored externally — all analysis results are saved locally on your machine in a database only you can access.',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <ellipse cx="12" cy="5" rx="8" ry="3" />
        <path d="M4 5v14c0 1.66 3.58 3 8 3s8-1.34 8-3V5" />
        <path d="M4 12c0 1.66 3.58 3 8 3s8-1.34 8-3" />
      </svg>
    ),
  },
  {
    text: 'No account required — download, install, and run. No signup, no license key, no phone home.',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="11" width="18" height="10" rx="2" />
        <path d="M7 11V7a5 5 0 0 1 9.9-1" />
      </svg>
    ),
  },
]

export default function HomePage() {
  return (
    <div>
      <section className="max-w-4xl mx-auto px-6 pt-20 pb-10 text-center">
        <h1 className="text-4xl sm:text-5xl font-extrabold text-text-primary tracking-tight leading-tight">
          Find What Your SIEM Missed
        </h1>
        <p className="mt-6 text-lg text-text-secondary max-w-2xl mx-auto leading-relaxed">
          DimSense automatically identifies the most analytically useful fields
          in your EDR logs and surfaces coordinated behavioral anomalies that
          rule-based detection was never designed to catch.
        </p>

        <div className="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4">
          <Link
            to="/download"
            className="inline-flex items-center justify-center rounded-lg bg-accent px-6 py-3 text-sm font-semibold text-white hover:bg-accent/90 transition-colors w-full sm:w-auto"
          >
            Download Free
          </Link>
          <Link
            to="/demo"
            className="inline-flex items-center justify-center rounded-lg border border-border bg-card px-6 py-3 text-sm font-semibold text-text-primary hover:border-accent/60 transition-colors w-full sm:w-auto"
          >
            Try Online
          </Link>
        </div>

        <div className="mt-6 max-w-2xl mx-auto rounded-lg border border-accent/30 bg-accent/10 px-4 py-3 text-sm text-text-primary text-left leading-relaxed">
          <span className="font-semibold text-accent">Note:</span> The online
          version is for evaluation only. Use synthetic test data or data you
          have already anonymized — do not upload real sensitive logs to the
          online tool. For real data, download the free desktop app. Your data
          never leaves your machine.
        </div>
      </section>

      <section className="max-w-5xl mx-auto px-6 py-16">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
          {HOW_IT_WORKS.map((card) => (
            <div key={card.title} className="rounded-xl border border-border bg-card p-6">
              <h3 className="text-lg font-semibold text-text-primary mb-2">
                {card.title}
              </h3>
              <p className="text-sm text-text-secondary leading-relaxed">
                {card.description}
              </p>
            </div>
          ))}
        </div>
      </section>

      <section className="max-w-3xl mx-auto px-6 py-16">
        <h2 className="text-2xl sm:text-3xl font-bold text-text-primary text-center mb-6 leading-tight">
          Your SIEM Has the Data. Finding the Signal Is the Hard Part.
        </h2>
        <div className="text-text-secondary leading-relaxed space-y-4">
          <p>
            Security teams spend hours writing queries, tuning rules, and
            chasing alerts — all starting from a blank search box with
            hundreds of fields and no systematic way to know which ones
            matter for this dataset, right now.
          </p>
          <p>
            DimSense does not replace your SIEM. It tells you where to look.
            Upload your logs, and within seconds you have a ranked list of the
            fields with the strongest analytical signal, a time series showing
            when behavior shifted, and a plain English summary of what
            changed and what to investigate next.
          </p>
          <p>
            You stay in control. The algorithm makes recommendations — you
            decide which fields to monitor and can override any suggestion
            before analysis runs.
          </p>
        </div>
      </section>

      <section className="max-w-3xl mx-auto px-6 py-16 text-center">
        <h2 className="text-2xl sm:text-3xl font-bold text-text-primary mb-6">
          Test It On Something You Already Know
        </h2>
        <div className="text-text-secondary leading-relaxed space-y-4 text-left">
          <p>
            The best way to evaluate DimSense is to run it against a time
            period where you already know something happened — a past
            incident, a breach, an alert that turned out to be real.
          </p>
          <p>
            Download the free desktop app, export a CSV covering that time
            window from your EDR, and upload it. If DimSense flags the right
            window with a high confidence score, you have your answer. If it
            doesn't, we want to know.
          </p>
        </div>
        <Link
          to="/download"
          className="mt-8 inline-flex items-center justify-center rounded-lg bg-accent px-6 py-3 text-sm font-semibold text-white hover:bg-accent/90 transition-colors"
        >
          Download Free Desktop App
        </Link>
      </section>

      <section className="max-w-3xl mx-auto px-6 py-16">
        <h2 className="text-2xl sm:text-3xl font-bold text-text-primary text-center mb-10">
          Your Data Stays Yours
        </h2>
        <div className="space-y-6">
          {PRIVACY_POINTS.map((point) => (
            <div key={point.text} className="flex items-start gap-4">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-accent/15 text-accent [&>svg]:h-5 [&>svg]:w-5">
                {point.icon}
              </div>
              <p className="text-text-secondary leading-relaxed pt-1.5">
                {point.text}
              </p>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}
