import { useState } from 'react'
import { Link, NavLink, Outlet } from 'react-router-dom'
import { actor, setActor } from '../lib/actor'

export function Layout() {
  const [name, setName] = useState(actor())

  return (
    <>
      <header>
        <Link to="/" className="brand">
          ShellSight
        </Link>
        <nav>
          <NavLink to="/">Cases</NavLink>
          <NavLink to="/rules">Rules</NavLink>
          <NavLink to="/rulesets">Rule sets</NavLink>
          <NavLink to="/generate">Generate</NavLink>
        </nav>

        {/* The analyst's name is configuration: set once, then true for the shift. It used to hold
            the top-right of every screen as a labelled input plus two lines of prose about what
            the name does and does not prove -- roughly 60px of vertical space, on every render,
            forever. As a chip it costs a line of the header and still opens in one click, and the
            caveat that made it worth saying is inside where it is read at the moment it matters. */}
        <details className="identity">
          <summary>
            <span className={`identity-dot${name.trim() === '' ? ' anon' : ''}`} />
            {name.trim() === '' ? 'unattributed' : name}
          </summary>
          <div className="identity-panel">
            <label htmlFor="actor">Your name</label>
            <input
              id="actor"
              value={name}
              placeholder="unattributed"
              onChange={(e) => {
                setName(e.target.value)
                setActor(e.target.value)
              }}
            />
            <p className="muted small" style={{ margin: 'var(--s2) 0 0' }}>
              Recorded against your decisions. Attribution, not authentication — the console
              accepts whatever this says.
            </p>
          </div>
        </details>
      </header>
      <main>
        <Outlet />
      </main>
    </>
  )
}
