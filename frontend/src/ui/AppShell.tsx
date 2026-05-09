import { Outlet, Link, useLocation } from 'react-router-dom'
import { Shield, FileSearch, ExternalLink } from 'lucide-react'
import { cn } from '@/lib/cn'

export function AppShell() {
  const loc = useLocation()

  return (
    <div className="min-h-dvh bg-slate-950">
      <header className="sticky top-0 z-10 border-b border-slate-800/80 bg-slate-950/80 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-4">
          <Link to="/" className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-xl border border-slate-800 bg-slate-900 shadow-glow">
              <Shield className="h-5 w-5 text-cyan-300" />
            </div>
            <div className="leading-tight">
              <div className="text-sm font-semibold tracking-wide text-slate-100">BinaryWatch</div>
              <div className="text-xs text-slate-400">Binary analysis report viewer</div>
            </div>
          </Link>

          <nav className="flex items-center gap-2">
            <Link
              to="/"
              className={cn(
                'inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm transition',
                'border-slate-800 bg-slate-900/40 text-slate-200 hover:bg-slate-900',
                loc.pathname === '/' && 'border-cyan-500/40 bg-slate-900 text-white'
              )}
            >
              <FileSearch className="h-4 w-4" />
              Search
            </Link>
            <a
              href="http://127.0.0.1:8000/docs"
              target="_blank"
              rel="noreferrer"
              className={cn(
                'inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm transition',
                'border-slate-800 bg-slate-900/40 text-slate-200 hover:bg-slate-900'
              )}
              title="Open backend Swagger docs"
            >
              API Docs <ExternalLink className="h-4 w-4" />
            </a>
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-8">
        <Outlet />
      </main>

      <footer className="border-t border-slate-800/70 py-8">
        <div className="mx-auto max-w-6xl px-4 text-xs text-slate-500">
          Built for SOC workflows. Backend must be running for live queries.
        </div>
      </footer>
    </div>
  )
}

