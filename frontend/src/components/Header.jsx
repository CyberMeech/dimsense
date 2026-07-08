import { NavLink, Link } from 'react-router-dom'

const navLinkClass = ({ isActive }) =>
  `text-sm font-medium transition-colors ${
    isActive ? 'text-text-primary' : 'text-text-secondary hover:text-text-primary'
  }`

export default function Header() {
  return (
    <header className="border-b border-border bg-bg/95 backdrop-blur sticky top-0 z-50">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 py-4 flex items-center justify-between gap-4">
        <Link to="/" className="flex flex-col shrink-0">
          <span className="text-lg font-bold text-text-primary tracking-tight">
            DimSense
          </span>
          <span className="text-xs text-text-secondary hidden md:block">
            Upload your EDR logs. Detect what your alerts missed.
          </span>
        </Link>
        <nav className="flex items-center gap-3 sm:gap-6 flex-wrap justify-end">
          <NavLink to="/" className={navLinkClass} end>
            Home
          </NavLink>
          <NavLink to="/demo" className={navLinkClass}>
            Try Online
          </NavLink>
          <NavLink to="/download" className={navLinkClass}>
            Download
          </NavLink>
          <NavLink to="/about" className={navLinkClass}>
            About
          </NavLink>
        </nav>
      </div>
    </header>
  )
}
