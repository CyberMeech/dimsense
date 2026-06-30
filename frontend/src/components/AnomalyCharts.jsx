import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ReferenceArea,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

const LINE_COLORS = [
  '#3b82f6',
  '#10b981',
  '#f59e0b',
  '#ef4444',
  '#a855f7',
  '#06b6d4',
  '#ec4899',
  '#84cc16',
  '#f97316',
  '#6366f1',
  '#14b8a6',
  '#eab308',
]

function buildChartData(windows) {
  return windows.map((w) => {
    const row = {
      window_index: w.window_index,
      event_rate_per_hour: w.event_rate_per_hour,
    }
    for (const stat of w.field_stats) {
      row[`${stat.field_name}__n_max`] = stat.n_max
      row[`${stat.field_name}__n_unique`] = stat.n_unique
    }
    return row
  })
}

function FlaggedAreas({ flaggedIndices }) {
  return flaggedIndices.map((index) => (
    <ReferenceArea
      key={index}
      x1={index - 0.5}
      x2={index + 0.5}
      fill="#ef4444"
      fillOpacity={0.18}
      stroke="none"
      ifOverflow="visible"
    />
  ))
}

function ChartCard({ title, children }) {
  return (
    <div className="rounded-xl border border-border bg-card p-6">
      <h3 className="text-base font-semibold text-text-primary mb-4">{title}</h3>
      <ResponsiveContainer width="100%" height={340}>
        {children}
      </ResponsiveContainer>
    </div>
  )
}

const CHART_MARGIN = { top: 8, right: 24, left: 4, bottom: 32 }
const axisStyle = { fill: '#8892a4', fontSize: 12 }
const xAxisLabelStyle = { value: 'Window index', position: 'insideBottom', offset: 8, fill: '#8892a4', fontSize: 12 }
const legendStyle = { fontSize: 12, color: '#8892a4', paddingTop: 16 }
const tooltipStyle = {
  backgroundColor: '#1a1d27',
  border: '1px solid #2a2d3e',
  borderRadius: 8,
  color: '#e2e8f0',
  fontSize: 12,
}

export default function AnomalyCharts({ windows, fields }) {
  const chartData = buildChartData(windows)
  const flaggedIndices = windows.filter((w) => w.is_flagged).map((w) => w.window_index)

  return (
    <section className="max-w-6xl mx-auto px-6 py-12">
      <h2 className="text-2xl font-bold text-text-primary">Temporal Analysis</h2>
      <p className="mt-2 text-text-secondary max-w-2xl">
        Each point represents a window of 8,192 events. Flagged windows are
        highlighted in red.
      </p>

      <div className="mt-6 space-y-6">
        <ChartCard title="Event Rate Over Time">
          <LineChart data={chartData} margin={CHART_MARGIN}>
            <CartesianGrid stroke="#2a2d3e" strokeDasharray="3 3" />
            <XAxis
              dataKey="window_index"
              type="number"
              domain={['dataMin', 'dataMax']}
              allowDecimals={false}
              height={50}
              tick={axisStyle}
              label={xAxisLabelStyle}
            />
            <YAxis
              tick={axisStyle}
              label={{ value: 'Events / hour', angle: -90, position: 'insideLeft', fill: '#8892a4', fontSize: 12 }}
            />
            <Tooltip contentStyle={tooltipStyle} />
            <FlaggedAreas flaggedIndices={flaggedIndices} />
            <Line
              type="monotone"
              dataKey="event_rate_per_hour"
              name="Event rate"
              stroke="#3b82f6"
              dot={false}
              strokeWidth={2}
            />
          </LineChart>
        </ChartCard>

        <ChartCard title="Concentration — Max Value Frequency Per Field">
          <LineChart data={chartData} margin={CHART_MARGIN}>
            <CartesianGrid stroke="#2a2d3e" strokeDasharray="3 3" />
            <XAxis
              dataKey="window_index"
              type="number"
              domain={['dataMin', 'dataMax']}
              allowDecimals={false}
              height={50}
              tick={axisStyle}
              label={xAxisLabelStyle}
            />
            <YAxis
              tick={axisStyle}
              label={{ value: 'n_max', angle: -90, position: 'insideLeft', fill: '#8892a4', fontSize: 12 }}
            />
            <Tooltip contentStyle={tooltipStyle} />
            <Legend wrapperStyle={legendStyle} />
            <FlaggedAreas flaggedIndices={flaggedIndices} />
            {fields.map((fieldName, i) => (
              <Line
                key={fieldName}
                type="monotone"
                dataKey={`${fieldName}__n_max`}
                name={fieldName}
                stroke={LINE_COLORS[i % LINE_COLORS.length]}
                dot={false}
                strokeWidth={2}
              />
            ))}
          </LineChart>
        </ChartCard>

        <ChartCard title="Diversity — Unique Value Count Per Field">
          <LineChart data={chartData} margin={CHART_MARGIN}>
            <CartesianGrid stroke="#2a2d3e" strokeDasharray="3 3" />
            <XAxis
              dataKey="window_index"
              type="number"
              domain={['dataMin', 'dataMax']}
              allowDecimals={false}
              height={50}
              tick={axisStyle}
              label={xAxisLabelStyle}
            />
            <YAxis
              tick={axisStyle}
              label={{ value: 'n_unique', angle: -90, position: 'insideLeft', fill: '#8892a4', fontSize: 12 }}
            />
            <Tooltip contentStyle={tooltipStyle} />
            <Legend wrapperStyle={legendStyle} />
            <FlaggedAreas flaggedIndices={flaggedIndices} />
            {fields.map((fieldName, i) => (
              <Line
                key={fieldName}
                type="monotone"
                dataKey={`${fieldName}__n_unique`}
                name={fieldName}
                stroke={LINE_COLORS[i % LINE_COLORS.length]}
                dot={false}
                strokeWidth={2}
              />
            ))}
          </LineChart>
        </ChartCard>
      </div>
    </section>
  )
}
