import { useRef, useState } from 'react'
import Spinner from './Spinner'

function previewCsv(file, callback) {
  const reader = new FileReader()
  reader.onload = () => {
    const text = reader.result
    const lines = text.split(/\r\n|\n|\r/).filter((line) => line.length > 0)
    const fieldCount = lines.length > 0 ? lines[0].split(',').length : 0
    const rowCount = Math.max(lines.length - 1, 0)
    callback({ rowCount, fieldCount })
  }
  reader.readAsText(file)
}

export default function UploadDropzone({ onAnalyze, loading }) {
  const [file, setFile] = useState(null)
  const [preview, setPreview] = useState(null)
  const [isDragging, setIsDragging] = useState(false)
  const inputRef = useRef(null)

  function pickFile(selected) {
    if (!selected) return
    setFile(selected)
    setPreview(null)
    previewCsv(selected, setPreview)
  }

  function handleDrop(e) {
    e.preventDefault()
    setIsDragging(false)
    const dropped = e.dataTransfer.files?.[0]
    pickFile(dropped)
  }

  function handleInputChange(e) {
    pickFile(e.target.files?.[0])
  }

  return (
    <div className="w-full max-w-2xl mx-auto">
      <div
        onDragOver={(e) => {
          e.preventDefault()
          setIsDragging(true)
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        className={`cursor-pointer rounded-xl border-2 border-dashed px-8 py-12 text-center transition-colors ${
          isDragging
            ? 'border-accent bg-accent/10'
            : 'border-border bg-card hover:border-accent/60'
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".csv"
          className="hidden"
          onChange={handleInputChange}
        />
        <p className="text-text-primary font-medium">
          Drop your EDR CSV here or click to browse
        </p>
        <p className="text-sm text-text-secondary mt-2">
          Supports any EDR export in CSV format. Max 500k rows.
        </p>
      </div>

      {file && (
        <div className="mt-4 rounded-lg border border-border bg-card px-4 py-3 flex items-center justify-between gap-4">
          <div className="text-sm text-text-primary truncate">
            <span className="font-medium">{file.name}</span>
            {preview && (
              <span className="text-text-secondary">
                {' '}
                &middot; {preview.rowCount.toLocaleString()} rows &middot;{' '}
                {preview.fieldCount.toLocaleString()} fields
              </span>
            )}
          </div>
        </div>
      )}

      {file && (
        <div className="mt-4 flex justify-center">
          <button
            type="button"
            disabled={loading}
            onClick={() => onAnalyze(file)}
            className="inline-flex items-center gap-2 rounded-lg bg-accent px-6 py-3 text-sm font-semibold text-white hover:bg-accent/90 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
          >
            {loading && <Spinner size="h-4 w-4" />}
            {loading ? 'Analyzing…' : 'Analyze'}
          </button>
        </div>
      )}
    </div>
  )
}
