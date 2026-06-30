export default function ErrorBanner({ message }) {
  if (!message) return null
  return (
    <div className="rounded-lg border border-danger/40 bg-danger/10 px-4 py-3 text-sm text-danger flex items-start gap-2">
      <span className="font-semibold">Error:</span>
      <span className="text-text-primary">{message}</span>
    </div>
  )
}
