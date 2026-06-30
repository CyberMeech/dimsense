function Section({ title, children }) {
  return (
    <section className="mb-12">
      <h2 className="text-xl font-bold text-text-primary mb-3">{title}</h2>
      <div className="text-text-secondary leading-relaxed space-y-3">{children}</div>
    </section>
  )
}

export default function AboutPage() {
  return (
    <div className="max-w-3xl mx-auto px-6 py-16">
      <h1 className="text-3xl font-bold text-text-primary mb-10">About DimSense</h1>

      <Section title="What DimSense does">
        <p>
          DimSense scans your EDR log exports and automatically figures out
          which fields are worth watching — without you having to write a
          single detection rule. It then breaks your logs into time windows
          and tracks how those fields behave over time, flagging the moments
          where several fields move together in an unusual way. That kind of
          coordinated shift is the signature of activity that rule-based
          alerting tends to miss.
        </p>
      </Section>

      <Section title="The research behind it">
        <p>
          DimSense is an implementation of the Big Data Dimensional Analysis
          method described in:
        </p>
        <p className="text-text-primary font-medium">
          Schofield, M. et al. "AI for Scalable Defensive Cyber Log Analysis."
          MIT Lincoln Laboratory / U.S. Air Force, 2025.
        </p>
        <p>
          The paper proposes scoring every field in a log source along three
          statistical dimensions — coverage, diversity, and concentration —
          to automatically surface the fields with the strongest analytical
          signal, then monitoring those fields over rolling time windows to
          detect coordinated behavioral shifts.
        </p>
      </Section>

      <Section title="The three metric filters, explained simply">
        <p>
          <span className="text-text-primary font-medium">Coverage (n_nonempty):</span>{' '}
          How often a field actually has a value. A field that's empty most of
          the time isn't reliable enough to analyze.
        </p>
        <p>
          <span className="text-text-primary font-medium">Diversity (n_unique):</span>{' '}
          How many distinct values a field takes on. Fields with almost no
          variation (constants) or far too much variation (unique IDs,
          hashes) don't carry a useful pattern.
        </p>
        <p>
          <span className="text-text-primary font-medium">Concentration (n_max):</span>{' '}
          How often the single most common value appears. This separates
          fields with a meaningful "normal" distribution from fields that are
          either dominated by one value or have no repeating structure at
          all.
        </p>
      </Section>

      <Section title="What different anomaly patterns mean">
        <p>
          <span className="text-text-primary font-medium">Coordinated:</span>{' '}
          Event volume, concentration, and diversity all spike together —
          the highest-confidence signal, consistent with C2 callbacks or
          coordinated lateral movement.
        </p>
        <p>
          <span className="text-text-primary font-medium">Concentrated:</span>{' '}
          A small number of entities suddenly dominate activity while overall
          participation stays normal — often beaconing or focused
          reconnaissance.
        </p>
        <p>
          <span className="text-text-primary font-medium">Broad:</span> More
          distinct entities are active than usual with no single dominant
          entity — often scanning or worm-like spread.
        </p>
        <p>
          <span className="text-text-primary font-medium">Volume spike:</span>{' '}
          Activity increases without a distributional shift — often a
          scheduled job or benign workload spike, lower confidence.
        </p>
        <p>
          <span className="text-text-primary font-medium">Quiet concentration:</span>{' '}
          Normal volume but activity consolidates around fewer entities than
          baseline — a potential sign of low-and-slow activity designed to
          avoid volume-based detection.
        </p>
      </Section>

      <Section title="Who this is for">
        <p>
          DimSense is built for security analysts at mid-market
          organizations — teams that have an EDR generating plenty of log
          data, but lack the time or headcount to build and tune custom
          detection rules for every dataset they collect.
        </p>
      </Section>
    </div>
  )
}
