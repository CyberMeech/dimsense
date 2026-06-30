const STEPS = [
  {
    number: '1',
    title: 'Upload',
    description: 'Upload any EDR CSV export.',
  },
  {
    number: '2',
    title: 'Analyze',
    description: 'Algorithm scores every field using proven MIT/USAF methodology.',
  },
  {
    number: '3',
    title: 'Detect',
    description:
      'See coordinated anomalies visualized with plain English explanations.',
  },
]

export default function HowItWorks() {
  return (
    <section className="max-w-5xl mx-auto px-6 py-20">
      <h2 className="text-2xl font-bold text-text-primary text-center mb-10">
        How it works
      </h2>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
        {STEPS.map((step) => (
          <div
            key={step.number}
            className="rounded-xl border border-border bg-card p-6"
          >
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-accent/15 text-accent font-bold mb-4">
              {step.number}
            </div>
            <h3 className="text-lg font-semibold text-text-primary mb-2">
              {step.title}
            </h3>
            <p className="text-sm text-text-secondary leading-relaxed">
              {step.description}
            </p>
          </div>
        ))}
      </div>
    </section>
  )
}
