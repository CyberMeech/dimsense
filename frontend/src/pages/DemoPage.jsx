import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import UploadDropzone from '../components/UploadDropzone'
import HowItWorks from '../components/HowItWorks'
import ErrorBanner from '../components/ErrorBanner'
import { uploadCsv, analyzeCsv } from '../api'

export default function DemoPage() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const navigate = useNavigate()

  async function handleAnalyze(file) {
    setLoading(true)
    setError(null)
    try {
      const upload = await uploadCsv(file)
      const analysis = await analyzeCsv(upload.session_id)
      navigate('/analysis', {
        state: {
          sessionId: upload.session_id,
          totalRecords: analysis.total_records,
          totalFields: analysis.total_fields,
          fields: analysis.fields,
        },
      })
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <div className="bg-warning/10 border-b border-warning/40">
        <div className="max-w-4xl mx-auto px-6 py-3 text-center">
          <p className="text-sm text-text-primary leading-relaxed">
            <span className="font-bold text-warning">You are using the online demo.</span>{' '}
            Do not upload real or sensitive log data here. Use synthetic test
            data or anonymized exports only. For real data analysis download
            the free desktop app.
          </p>
          <Link
            to="/download"
            className="mt-1 inline-block text-sm font-semibold text-accent hover:text-accent/80"
          >
            Download the free desktop app →
          </Link>
        </div>
      </div>

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
          <UploadDropzone onAnalyze={handleAnalyze} loading={loading} />
        </div>

        {error && (
          <div className="mt-6 max-w-2xl mx-auto text-left">
            <ErrorBanner message={error} />
          </div>
        )}
      </section>

      <HowItWorks />
    </div>
  )
}
