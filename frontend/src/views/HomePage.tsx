import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, ArrowRight, Hash } from 'lucide-react'
import { cn } from '@/lib/cn'

function normalizeHash(input: string) {
  return input.trim().toLowerCase()
}

function isSha256(input: string) {
  return /^[a-f0-9]{64}$/.test(input)
}

const RECENTS_KEY = 'triageengine.recents.v1'

function readRecents(): string[] {
  try {
    const raw = localStorage.getItem(RECENTS_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw) as unknown
    if (!Array.isArray(parsed)) return []
    return parsed.filter((x) => typeof x === 'string' && isSha256(x)).slice(0, 10)
  } catch {
    return []
  }
}

function writeRecent(hash: string) {
  const recents = [hash, ...readRecents().filter((x) => x !== hash)].slice(0, 10)
  localStorage.setItem(RECENTS_KEY, JSON.stringify(recents))
}

export function HomePage() {
  const nav = useNavigate()
  const [fileHash, setFileHash] = useState('')
  const [touched, setTouched] = useState(false)
  const recents = useMemo(() => readRecents(), [])

  const normalized = normalizeHash(fileHash)
  const valid = isSha256(normalized)

  function go(hash: string) {
    const h = normalizeHash(hash)
    if (!isSha256(h)) return
    writeRecent(h)
    nav(`/report/${h}`)
  }

  return (
    <div className="grid gap-6">
      <section className="rounded-2xl border border-slate-800 bg-gradient-to-b from-slate-900/60 to-slate-950 p-6 shadow-glow">
        <div className="flex items-start justify-between gap-6">
          <div className="max-w-2xl">
            <h1 className="text-2xl font-semibold tracking-tight text-slate-100">Report search</h1>
            <p className="mt-2 text-sm text-slate-400">
              Paste a SHA256 and fetch the cached analysis report from the backend database.
            </p>
          </div>
          <div className="hidden rounded-xl border border-slate-800 bg-slate-900/50 px-3 py-2 text-xs text-slate-400 md:block">
            Tip: Start with the sample’s SHA256 from your triage pipeline.
          </div>
        </div>

        <div className="mt-6 grid gap-3 md:grid-cols-[1fr_auto] md:items-end">
          <label className="grid gap-2">
            <span className="text-xs font-medium text-slate-300">SHA256</span>
            <div
              className={cn(
                'flex items-center gap-2 rounded-xl border bg-slate-950 px-3 py-2',
                touched && !valid ? 'border-rose-500/60' : 'border-slate-800'
              )}
            >
              <Hash className="h-4 w-4 text-slate-500" />
              <input
                value={fileHash}
                onChange={(e) => setFileHash(e.target.value)}
                onBlur={() => setTouched(true)}
                placeholder="e.g. 1ccf6eab61dabb654504fab6d70876d7bcbeba2140e27e3e3279ed0eabdb988a"
                className="w-full bg-transparent font-mono text-sm text-slate-100 placeholder:text-slate-600 outline-none"
                spellCheck={false}
                autoCapitalize="none"
                autoCorrect="off"
              />
            </div>
            {touched && !valid ? (
              <div className="text-xs text-rose-300">Enter a valid 64-hex SHA256.</div>
            ) : (
              <div className="text-xs text-slate-500">Only lowercase/uppercase hex is accepted.</div>
            )}
          </label>

          <button
            onClick={() => go(normalized)}
            disabled={!valid}
            className={cn(
              'inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold transition',
              valid
                ? 'bg-cyan-500 text-slate-950 hover:bg-cyan-400'
                : 'cursor-not-allowed bg-slate-800 text-slate-400'
            )}
          >
            <Search className="h-4 w-4" />
            Fetch report
            <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      </section>

      <section className="grid gap-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200">Recent hashes</h2>
          <div className="text-xs text-slate-500">Stored locally in your browser</div>
        </div>

        {recents.length === 0 ? (
          <div className="rounded-xl border border-slate-800 bg-slate-900/30 p-4 text-sm text-slate-400">
            No recent lookups yet.
          </div>
        ) : (
          <div className="grid gap-2">
            {recents.map((h) => (
              <button
                key={h}
                onClick={() => go(h)}
                className="flex items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-900/30 px-4 py-3 text-left text-sm transition hover:bg-slate-900"
              >
                <span className="truncate font-mono text-slate-200">{h}</span>
                <span className="shrink-0 text-xs text-slate-400">Open</span>
              </button>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}

