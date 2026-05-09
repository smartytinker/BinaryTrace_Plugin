import { useMemo } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, ArrowLeft, CheckCircle2, Copy, Network, ShieldAlert } from 'lucide-react'
import { cn } from '@/lib/cn'
import { ApiError, getIocs, getReport } from '@/lib/api'

function isSha256(input: string) {
  return /^[a-f0-9]{64}$/i.test(input)
}

function riskBadge(score: number) {
  if (score >= 75) return { label: 'CRITICAL', className: 'bg-rose-500/15 text-rose-200 border-rose-500/30' }
  if (score >= 50) return { label: 'HIGH', className: 'bg-amber-500/15 text-amber-200 border-amber-500/30' }
  if (score >= 25) return { label: 'MEDIUM', className: 'bg-yellow-500/15 text-yellow-200 border-yellow-500/30' }
  return { label: 'LOW', className: 'bg-emerald-500/15 text-emerald-200 border-emerald-500/30' }
}

function ClipboardButton({ text }: { text: string }) {
  return (
    <button
      onClick={async () => navigator.clipboard.writeText(text)}
      className="inline-flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/30 px-3 py-2 text-xs text-slate-200 transition hover:bg-slate-900"
      title="Copy to clipboard"
    >
      <Copy className="h-3.5 w-3.5" />
      Copy
    </button>
  )
}

export function ReportPage() {
  const { fileHash } = useParams()
  const hash = (fileHash || '').trim()
  const valid = isSha256(hash)

  const reportQ = useQuery({
    queryKey: ['report', hash],
    queryFn: () => getReport(hash),
    enabled: valid,
  })

  const iocsQ = useQuery({
    queryKey: ['iocs', hash],
    queryFn: () => getIocs(hash),
    enabled: valid,
  })

  const combinedError = reportQ.error || iocsQ.error
  const report = reportQ.data
  const iocs = iocsQ.data

  const badge = useMemo(() => (report ? riskBadge(report.risk_assessment.score) : null), [report])

  if (!valid) {
    return (
      <div className="grid gap-4">
        <Link to="/" className="inline-flex items-center gap-2 text-sm text-slate-300 hover:text-white">
          <ArrowLeft className="h-4 w-4" /> Back
        </Link>
        <div className="rounded-2xl border border-rose-500/30 bg-rose-500/10 p-6 text-slate-200">
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-0.5 h-5 w-5 text-rose-300" />
            <div>
              <div className="text-lg font-semibold">Invalid SHA256</div>
              <div className="mt-1 text-sm text-slate-300">
                The URL must contain a 64-hex SHA256 hash.
              </div>
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="grid gap-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Link to="/" className="inline-flex items-center gap-2 text-sm text-slate-300 hover:text-white">
          <ArrowLeft className="h-4 w-4" /> Back
        </Link>
        <div className="flex items-center gap-2">
          <ClipboardButton text={hash} />
        </div>
      </div>

      <section className="rounded-2xl border border-slate-800 bg-slate-900/30 p-6 shadow-glow">
        <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
          <div>
            <div className="text-xs font-semibold tracking-wide text-slate-400">SHA256</div>
            <div className="mt-1 break-all font-mono text-sm text-slate-100">{hash}</div>
            {report?.file ? <div className="mt-2 text-xs text-slate-500">Target: {report.file}</div> : null}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {badge ? (
              <div className={cn('rounded-xl border px-3 py-2 text-xs font-semibold', badge.className)}>
                Risk: {report!.risk_assessment.score}/100 ({badge.label})
              </div>
            ) : (
              <div className="rounded-xl border border-slate-800 px-3 py-2 text-xs text-slate-400">
                Risk: —
              </div>
            )}
            {report ? (
              <div className="rounded-xl border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-300">
                Packed: <span className="font-semibold">{report.packer_info.is_packed ? 'Yes' : 'No'}</span>
              </div>
            ) : null}
          </div>
        </div>

        <div className="mt-4 grid gap-3 md:grid-cols-3">
          <StatusTile
            title="Report"
            loading={reportQ.isLoading}
            ok={!!report}
            error={reportQ.error}
            icon={<ShieldAlert className="h-4 w-4" />}
          />
          <StatusTile
            title="IOCs"
            loading={iocsQ.isLoading}
            ok={!!iocs}
            error={iocsQ.error}
            icon={<Network className="h-4 w-4" />}
          />
          <StatusTile
            title="Backend response"
            loading={reportQ.isLoading || iocsQ.isLoading}
            ok={!!report && !!iocs}
            error={combinedError}
            icon={<CheckCircle2 className="h-4 w-4" />}
          />
        </div>
      </section>

      {combinedError ? (
        <ErrorPanel error={combinedError} />
      ) : null}

      {report ? (
        <div className="grid gap-6">
          <section className="grid gap-4 md:grid-cols-2">
            <Card title="Risk reasons">
              {report.risk_assessment.reasons.length === 0 ? (
                <Empty>No reasons provided.</Empty>
              ) : (
                <ul className="grid gap-2 text-sm text-slate-200">
                  {report.risk_assessment.reasons.map((r) => (
                    <li key={r} className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
                      {r}
                    </li>
                  ))}
                </ul>
              )}
            </Card>

            <Card title="Threat intel">
              <div className="grid gap-2 text-sm text-slate-200">
                <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
                  <span className="text-slate-300">VirusTotal</span>
                  <span className="font-semibold">
                    {report.threat_intel.vt_positives} / {report.threat_intel.vt_total}
                  </span>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
                  <div className="text-slate-300">AbuseIPDB flagged IPs</div>
                  {Object.keys(report.threat_intel.malicious_ips || {}).length === 0 ? (
                    <div className="mt-1 text-xs text-slate-500">None.</div>
                  ) : (
                    <ul className="mt-2 grid gap-1 text-xs text-slate-200">
                      {Object.entries(report.threat_intel.malicious_ips).map(([ip, score]) => (
                        <li key={ip} className="flex items-center justify-between font-mono">
                          <span>{ip}</span>
                          <span className="text-amber-200">{score}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </Card>
          </section>

          <section className="grid gap-4 md:grid-cols-2">
            <Card title="Network IOCs">
              <div className="grid gap-4">
                <div>
                  <div className="text-xs font-semibold tracking-wide text-slate-400">URLs</div>
                  {iocs?.urls?.length ? (
                    <ul className="mt-2 grid gap-2">
                      {iocs.urls.map((u) => (
                        <li key={u} className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
                          <span className="break-all font-mono text-xs text-slate-100">{u}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <Empty className="mt-2">No URLs found.</Empty>
                  )}
                </div>
                <div>
                  <div className="text-xs font-semibold tracking-wide text-slate-400">IPs</div>
                  {iocs?.ips?.length ? (
                    <ul className="mt-2 grid gap-2">
                      {iocs.ips.map((ip) => (
                        <li key={ip} className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
                          <span className="font-mono text-xs text-slate-100">{ip}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <Empty className="mt-2">No IPs found.</Empty>
                  )}
                </div>
              </div>
            </Card>

            <Card title="Capabilities (MITRE)">
              {report.capabilities.length === 0 ? (
                <Empty>No MITRE capabilities mapped.</Empty>
              ) : (
                <div className="grid gap-2">
                  {report.capabilities.map((c) => (
                    <div key={`${c.technique_id}-${c.tactic}`} className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="font-semibold text-slate-100">{c.technique_id}</div>
                        <div className="text-xs text-slate-400">{c.tactic}</div>
                      </div>
                      <div className="mt-1 text-sm text-slate-200">{c.description}</div>
                      {c.evidence?.length ? (
                        <div className="mt-2 flex flex-wrap gap-2">
                          {c.evidence.map((e) => (
                            <span
                              key={e}
                              className="rounded-md border border-slate-800 bg-slate-900 px-2 py-1 font-mono text-[11px] text-slate-200"
                            >
                              {e}
                            </span>
                          ))}
                        </div>
                      ) : null}
                    </div>
                  ))}
                </div>
              )}
            </Card>
          </section>

          <section className="grid gap-4 md:grid-cols-2">
            <Card title="Suspicious imports">
              {report.suspicious_imports.length === 0 ? (
                <Empty>No suspicious imports detected.</Empty>
              ) : (
                <div className="grid gap-2">
                  {report.suspicious_imports.map((imp) => (
                    <div
                      key={`${imp.api}-${imp.address}`}
                      className="flex items-center justify-between gap-3 rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2"
                    >
                      <div className="min-w-0">
                        <div className="truncate font-mono text-xs text-slate-100">{imp.api}</div>
                        <div className="text-[11px] text-slate-500">{imp.category}</div>
                      </div>
                      <div className="shrink-0 font-mono text-[11px] text-slate-400">{imp.address}</div>
                    </div>
                  ))}
                </div>
              )}
            </Card>

            <Card title="Evasion & packing">
              <div className="grid gap-2 text-sm text-slate-200">
                <Row label="Packed">{report.packer_info.is_packed ? 'Yes' : 'No'}</Row>
                <Row label="Suspected packer">{report.packer_info.suspected_packer || 'None'}</Row>
                <Row label="Anti-debug">{report.evasion_info.uses_anti_debug ? 'Yes' : 'No'}</Row>
                <Row label="Anti-VM">{report.evasion_info.uses_anti_vm ? 'Yes' : 'No'}</Row>
                {report.evasion_info.anti_debug_apis_found?.length ? (
                  <div className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
                    <div className="text-xs font-semibold tracking-wide text-slate-400">Anti-debug APIs</div>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {report.evasion_info.anti_debug_apis_found.map((a) => (
                        <span key={a} className="rounded-md border border-slate-800 bg-slate-900 px-2 py-1 font-mono text-[11px] text-slate-200">
                          {a}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>
            </Card>
          </section>

          <section className="grid gap-4">
            <Card title="Top suspicious functions">
              {report.top_suspicious_functions.length === 0 ? (
                <Empty>No functions ranked.</Empty>
              ) : (
                <div className="grid gap-3">
                  {report.top_suspicious_functions.map((f) => (
                    <div key={`${f.name}-${f.address}`} className="rounded-xl border border-slate-800 bg-slate-950/40 p-4">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="min-w-0">
                          <div className="truncate font-semibold text-slate-100">{f.name}</div>
                          <div className="mt-1 font-mono text-xs text-slate-400">{f.address}</div>
                        </div>
                        <div className="rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs text-slate-200">
                          Score: <span className="font-semibold">{f.suspicion_score}</span>
                        </div>
                      </div>
                      {f.reasons?.length ? (
                        <ul className="mt-3 grid gap-2 text-sm text-slate-200">
                          {f.reasons.map((r) => (
                            <li key={r} className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
                              {r}
                            </li>
                          ))}
                        </ul>
                      ) : null}
                    </div>
                  ))}
                </div>
              )}
            </Card>
          </section>
        </div>
      ) : null}
    </div>
  )
}

function StatusTile({
  title,
  loading,
  ok,
  error,
  icon,
}: {
  title: string
  loading: boolean
  ok: boolean
  error: unknown
  icon: React.ReactNode
}) {
  const state = loading ? 'loading' : ok ? 'ok' : error ? 'error' : 'idle'
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/40 px-4 py-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-xs font-semibold tracking-wide text-slate-400">
          <span className="text-slate-500">{icon}</span>
          {title}
        </div>
        <div
          className={cn(
            'rounded-full border px-2 py-1 text-[11px] font-semibold',
            state === 'ok' && 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200',
            state === 'loading' && 'border-slate-700 bg-slate-900 text-slate-300',
            state === 'error' && 'border-rose-500/30 bg-rose-500/10 text-rose-200',
            state === 'idle' && 'border-slate-800 bg-slate-900/30 text-slate-400'
          )}
        >
          {state}
        </div>
      </div>
    </div>
  )
}

function ErrorPanel({ error }: { error: unknown }) {
  let title = 'Request failed'
  let body: string | undefined

  if (error instanceof ApiError) {
    title = `Backend error (HTTP ${error.status})`
    body = typeof error.payload === 'string' ? error.payload : JSON.stringify(error.payload, null, 2)
  } else if (error instanceof Error) {
    body = error.message
  }

  return (
    <section className="rounded-2xl border border-rose-500/30 bg-rose-500/10 p-6">
      <div className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 h-5 w-5 text-rose-300" />
        <div className="min-w-0">
          <div className="text-lg font-semibold text-slate-100">{title}</div>
          {body ? (
            <pre className="mt-3 overflow-auto rounded-xl border border-rose-500/20 bg-slate-950/40 p-3 text-xs text-slate-200">
              {body}
            </pre>
          ) : null}
        </div>
      </div>
    </section>
  )
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-2xl border border-slate-800 bg-slate-900/30 p-5 shadow-glow">
      <div className="mb-3 text-sm font-semibold text-slate-100">{title}</div>
      {children}
    </section>
  )
}

function Empty({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn('rounded-xl border border-slate-800 bg-slate-950/30 p-4 text-sm text-slate-400', className)}>
      {children}
    </div>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2">
      <span className="text-slate-300">{label}</span>
      <span className="font-semibold text-slate-100">{children}</span>
    </div>
  )
}

