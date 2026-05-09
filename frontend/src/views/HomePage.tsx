import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Search, ArrowRight, Hash, Activity, ShieldAlert, Database } from 'lucide-react'
import { cn } from '@/lib/cn'
import { getStats } from '@/lib/api'

function isSha256(input: string) { return /^[a-f0-9]{64}$/i.test(input.trim()) }

export function HomePage() {
  const nav = useNavigate()
  const [fileHash, setFileHash] = useState('')
  
  // Fetch our new global stats!
  const statsQ = useQuery({ queryKey: ['stats'], queryFn: getStats })

  function go(hash: string) {
    if (isSha256(hash)) nav(`/report/${hash.trim().toLowerCase()}`)
  }

  return (
    <div className="grid gap-6">
      {/* Search Section */}
      <section className="rounded-2xl border border-slate-800 bg-gradient-to-b from-slate-900/60 to-slate-950 p-6 shadow-glow">
        <h1 className="text-2xl font-semibold tracking-tight text-slate-100">Global Database Search</h1>
        <p className="mt-2 text-sm text-slate-400">Fetch cached analysis reports instantly from the central database.</p>
        
        <div className="mt-6 flex items-center gap-3">
          <div className="flex w-full items-center gap-2 rounded-xl border border-slate-800 bg-slate-950 px-3 py-2 focus-within:border-cyan-500/50">
            <Hash className="h-4 w-4 text-slate-500" />
            <input
              value={fileHash}
              onChange={(e) => setFileHash(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && go(fileHash)}
              placeholder="Enter SHA256 Hash..."
              className="w-full bg-transparent font-mono text-sm text-slate-100 placeholder:text-slate-600 outline-none"
            />
          </div>
          <button
            onClick={() => go(fileHash)}
            disabled={!isSha256(fileHash)}
            className="inline-flex items-center gap-2 rounded-xl bg-cyan-500 px-6 py-2 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:opacity-50"
          >
            <Search className="h-4 w-4" /> Fetch
          </button>
        </div>
      </section>

      {/* Global Metrics Dashboard */}
      {statsQ.data ? (
        <>
          <div className="grid gap-4 md:grid-cols-3">
            <div className="rounded-2xl border border-slate-800 bg-slate-900/30 p-5">
              <div className="flex items-center gap-2 text-sm font-medium text-slate-400"><Database className="h-4 w-4 text-cyan-400"/> Total Samples</div>
              <div className="mt-2 text-3xl font-bold text-slate-100">{statsQ.data.total_samples}</div>
            </div>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/30 p-5">
              <div className="flex items-center gap-2 text-sm font-medium text-slate-400"><Activity className="h-4 w-4 text-amber-400"/> Average Risk</div>
              <div className="mt-2 text-3xl font-bold text-slate-100">{statsQ.data.average_risk}/100</div>
            </div>
            <div className="rounded-2xl border border-rose-500/30 bg-rose-500/10 p-5">
              <div className="flex items-center gap-2 text-sm font-medium text-rose-300"><ShieldAlert className="h-4 w-4"/> Critical Threats</div>
              <div className="mt-2 text-3xl font-bold text-rose-200">{statsQ.data.critical_samples}</div>
            </div>
          </div>

          <section className="rounded-2xl border border-slate-800 bg-slate-900/30 p-5">
            <h2 className="mb-4 text-sm font-semibold text-slate-200">Recent Global Analysis Activity</h2>
            <div className="grid gap-2">
              {statsQ.data.recent_activity.map((r) => (
                <button key={r.file_hash} onClick={() => go(r.file_hash)} className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950/40 px-4 py-3 text-left transition hover:bg-slate-900">
                  <div>
                    <div className="font-mono text-sm text-slate-200">{r.file_hash}</div>
                    <div className="text-xs text-slate-500">Target: {r.file_name} • {new Date(r.timestamp).toLocaleString()}</div>
                  </div>
                  <div className={cn("rounded-lg border px-3 py-1 text-xs font-semibold", r.risk_score >= 75 ? "border-rose-500/30 bg-rose-500/20 text-rose-300" : "border-slate-700 bg-slate-800 text-slate-300")}>
                    Risk: {r.risk_score}
                  </div>
                </button>
              ))}
            </div>
          </section>
        </>
      ) : null}
    </div>
  )
}