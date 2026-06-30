import { NavLink, Link } from 'react-router-dom'

const navLinkClass = ({ isActive }) =>
  `text-sm font-medium transition-colors ${
    isActive ? 'text-text-primary' : 'text-text-secondary hover:text-text-primary'
  }`

export default function Header() {
  return (
    <header className="border-b border-border bg-bg/95 backdrop-blur sticky top-0 z-50">
      <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
        <Link to="/" className="flex flex-col">
          <span className="text-lg font-bold text-text-primary tracking-tight">
            DimSense
          </span>
          <span className="text-xs text-text-secondary hidden sm:block">
            Upload your EDR logs. Detect what your alerts missed.
          </span>
        </Link>
        <nav className="flex items-center gap-6">
          <NavLink to="/" className={navLinkClass} end>
            Home
          </NavLink>
          <NavLink to="/about" className={navLinkClass}>
            About
          </NavLink>
        </nav>
      </div>
    </header>
  )
}
