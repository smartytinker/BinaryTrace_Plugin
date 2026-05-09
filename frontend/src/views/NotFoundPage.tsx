import { Link } from 'react-router-dom'

export function NotFoundPage() {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/30 p-8 shadow-glow">
      <div className="text-xl font-semibold text-slate-100">Not found</div>
      <div className="mt-2 text-sm text-slate-400">That page doesn’t exist.</div>
      <Link
        to="/"
        className="mt-6 inline-flex rounded-xl border border-slate-800 bg-slate-950/40 px-4 py-2 text-sm text-slate-200 hover:bg-slate-900"
      >
        Go to search
      </Link>
    </div>
  )
}

