import { useRef, useState } from 'react'
import { createPortal } from 'react-dom'

function formatNumber(n) {
  return n.toLocaleString()
}

function ReasonCell({ reason }) {
  const [tooltip, setTooltip] = useState(null)
  const textRef = useRef(null)

  const showTooltip = () => {
    const rect = textRef.current.getBoundingClientRect()
    const left = Math.min(
      Math.max(rect.left + rect.width / 2, 96),
      window.innerWidth - 96
    )
    setTooltip({ top: rect.top, left })
  }

  return (
    <td className="px-4 py-3 text-text-secondary max-w-xs">
      <div
        ref={textRef}
        className="truncate"
        onMouseEnter={showTooltip}
        onMouseLeave={() => setTooltip(null)}
      >
        {reason}
      </div>
      {tooltip &&
        createPortal(
          <div
            className="pointer-events-none fixed z-50 w-max max-w-sm -translate-x-1/2 -translate-y-[calc(100%+8px)] rounded-lg border border-border bg-card px-3 py-2 text-xs leading-relaxed text-text-primary shadow-lg"
            style={{ top: tooltip.top, left: tooltip.left }}
          >
            {reason}
          </div>,
          document.body
        )}
    </td>
  )
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
              <ReasonCell reason={field.plain_english_reason} />
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
