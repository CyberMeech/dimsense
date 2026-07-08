import { Link } from 'react-router-dom'

const DOWNLOAD_URL =
  'https://github.com/CyberMeech/dimsense/releases/download/v0.1.0/DimSense_0.1.0_x64-setup.exe'

const REQUIREMENTS = [
  'Windows 10 or Windows 11 (64-bit)',
  '4GB RAM minimum',
  'No Python or other software required',
]

const STEPS = [
  'Download the installer above',
  'Run DimSense_0.1.0_x64-setup.exe — Windows will show a security warning because this release is not yet code signed. Click More info then Run anyway to proceed. Code signing is in progress for the next release.',
  'Open DimSense from your Start menu and upload your first CSV',
]

const INCLUDED = [
  'Full dimensional analysis engine',
  'Automated field scoring and selection',
  'Anomaly detection with quantile-based scoring',
  'Plain English findings summary',
  'Local SQLite database — no cloud storage',
  'Works completely offline',
]

export default function DownloadPage() {
  return (
    <div className="max-w-3xl mx-auto px-6 py-16">
      <div className="text-center">
        <h1 className="text-4xl font-extrabold text-text-primary tracking-tight">
          Download DimSense
        </h1>
        <p className="mt-4 text-lg text-text-secondary">
          Free. Local. No dependencies.
        </p>
      </div>

      <div className="mt-10 rounded-xl border border-border bg-card p-6">
        <h2 className="text-sm font-semibold text-text-primary uppercase tracking-wide mb-3">
          System Requirements
        </h2>
        <ul className="space-y-2">
          {REQUIREMENTS.map((req) => (
            <li key={req} className="text-sm text-text-secondary flex items-start gap-2">
              <span className="text-accent">•</span>
              {req}
            </li>
          ))}
        </ul>
      </div>

      <div className="mt-8 text-center">
        <a
          href={DOWNLOAD_URL}
          className="inline-flex items-center justify-center rounded-lg bg-accent px-8 py-4 text-base font-semibold text-white hover:bg-accent/90 transition-colors"
        >
          Download for Windows — v0.1.0
        </a>
      </div>

      <div className="mt-12">
        <h2 className="text-xl font-bold text-text-primary mb-6">Installation</h2>
        <ol className="space-y-4">
          {STEPS.map((step, i) => (
            <li key={i} className="flex gap-4">
              <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-accent/15 text-accent text-sm font-bold">
                {i + 1}
              </span>
              <p className="text-text-secondary leading-relaxed pt-0.5">{step}</p>
            </li>
          ))}
        </ol>
      </div>

      <div className="mt-12 rounded-xl border border-border bg-card p-6">
        <h2 className="text-sm font-semibold text-text-primary uppercase tracking-wide mb-3">
          What's Included
        </h2>
        <ul className="space-y-2">
          {INCLUDED.map((item) => (
            <li key={item} className="text-sm text-text-secondary flex items-start gap-2">
              <span className="text-success">✓</span>
              {item}
            </li>
          ))}
        </ul>
      </div>

      <div className="mt-12 text-center border-t border-border pt-10">
        <h2 className="text-lg font-bold text-text-primary mb-2">
          Also available — Try Online
        </h2>
        <p className="text-text-secondary leading-relaxed">
          Not ready to install? Try the online demo with synthetic test data
          at{' '}
          <Link to="/demo" className="text-accent hover:text-accent/80 font-medium">
            dimsense.io/demo
          </Link>
          . Do not upload real sensitive logs to the online version.
        </p>
      </div>
    </div>
  )
}
