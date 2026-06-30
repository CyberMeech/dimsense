function formatNumber(n) {
  return n.toLocaleString()
}

export default function FieldTable({ fields, selected, onToggle }) {
  const sorted = [...fields].sort((a, b) => b.n_unique - a.n_unique)

  return (
    <div className="overflow-x-auto rounded-xl border border-border">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-card text-text-secondary text-left">
            <th className="px-4 py-3 font-medium">Field Name</th>
            <th className="px-4 py-3 font-medium">Coverage</th>
            <th className="px-4 py-3 font-medium">Diversity</th>
            <th className="px-4 py-3 font-medium">Concentration</th>
            <th className="px-4 py-3 font-medium">Status</th>
            <th className="px-4 py-3 font-medium">Recommended</th>
            <th className="px-4 py-3 font-medium">Monitor</th>
            <th className="px-4 py-3 font-medium">Reason</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((field) => (
            <tr
              key={field.field_name}
              className={`border-t border-border bg-bg border-l-4 ${
                field.passed_filter ? 'border-l-success/60' : 'border-l-border'
              }`}
            >
              <td className="px-4 py-3 text-text-primary font-medium whitespace-nowrap">
                {field.field_name}
              </td>
              <td className="px-4 py-3 text-text-secondary">
                {formatNumber(field.n_nonempty)}
              </td>
              <td className="px-4 py-3 text-text-secondary">
                {formatNumber(field.n_unique)}
              </td>
              <td className="px-4 py-3 text-text-secondary">
                {formatNumber(field.n_max)}
              </td>
              <td className="px-4 py-3">
                {field.passed_filter ? (
                  <span className="inline-flex items-center rounded-full bg-success/15 px-2.5 py-1 text-xs font-medium text-success">
                    Passed
                  </span>
                ) : (
                  <span className="inline-flex items-center rounded-full bg-danger/15 px-2.5 py-1 text-xs font-medium text-danger">
                    Failed
                  </span>
                )}
              </td>
              <td className="px-4 py-3">
                {field.algorithm_recommended ? (
                  <span className="text-success" aria-label="Recommended">
                    &#10003;
                  </span>
                ) : (
                  <span className="text-text-secondary" aria-label="Not recommended">
                    &#10007;
                  </span>
                )}
              </td>
              <td className="px-4 py-3">
                <input
                  type="checkbox"
                  checked={!!selected[field.field_name]}
                  onChange={() => onToggle(field.field_name)}
                  className="h-4 w-4 rounded accent-accent cursor-pointer"
                />
              </td>
              <td
                className="px-4 py-3 text-text-secondary max-w-xs truncate"
                title={field.plain_english_reason}
              >
                {field.plain_english_reason}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
