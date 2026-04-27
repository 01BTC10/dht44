/*
 * Wrapper for content pages: top nav + footer. Article body lives
 * inside <Outlet />.
 */

import { Link, NavLink, Outlet } from "react-router-dom";

const NAV = [
  { to: "/protocol", label: "Protocol" },
  { to: "/lib",      label: "Library"  },
  { to: "/blog",     label: "Blog"     },
  { to: "/dashboard/peers", label: "Live" },
  { to: "/about",    label: "About"    },
];

export default function SiteShell() {
  return (
    <div className="site">
      <header className="site-header">
        <Link to="/" className="brand">dht44</Link>
        <nav className="site-nav">
          {NAV.map(n => (
            <NavLink
              key={n.to}
              to={n.to}
              className={({ isActive }) => (isActive ? "active" : "")}
            >
              {n.label}
            </NavLink>
          ))}
        </nav>
        <a href="https://github.com/r2d2/bep44_dht"
           target="_blank" rel="noreferrer noopener"
           className="gh-link">GitHub →</a>
      </header>
      <main className="site-main">
        <Outlet />
      </main>
      <footer className="site-footer">
        <span>dht44 — BitTorrent Mainline DHT toolkit</span>
        <span className="small">MIT licensed · <a href="https://github.com/r2d2/bep44_dht">source on GitHub</a></span>
      </footer>
    </div>
  );
}
