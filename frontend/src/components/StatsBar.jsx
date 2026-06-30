function Stat({ label, value }) {
  return (
    <div className="flex flex-col">
      <span className="text-2xl font-bold text-text-primary">{value}</span>
      <span className="text-xs text-text-secondary mt-1">{label}</span>
    </div>
  )
}

export default function StatsBar({ totalFields, recommendedCount, selectedCount }) {
  return (
    <div className="rounded-xl border border-border bg-card px-6 py-5 flex flex-wrap gap-8">
      <Stat label="Total fields analyzed" value={totalFields} />
      <Stat label="Recommended by algorithm" value={recommendedCount} />
      <Stat label="Currently selected" value={selectedCount} />
    </div>
  )
}
