import { env } from './env'

export class ApiError extends Error {
  status: number
  payload?: unknown

  constructor(message: string, status: number, payload?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.payload = payload
  }
}

async function readJsonSafe(res: Response): Promise<unknown> {
  const text = await res.text()
  if (!text) return undefined
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

export async function apiGet<T>(path: string): Promise<T> {
  const url = env.apiBaseUrl ? new URL(path, env.apiBaseUrl).toString() : `/api${path}`
  const res = await fetch(url, {
    headers: { Accept: 'application/json' },
  })

  if (!res.ok) {
    const payload = await readJsonSafe(res)
    throw new ApiError(`HTTP ${res.status} for ${path}`, res.status, payload)
  }

  return (await res.json()) as T
}

export type IocsResponse = { file_hash: string; urls: string[]; ips: string[] }

export type AnalysisReport = {
  file: string
  risk_assessment: { score: number; reasons: string[] }
  iocs: { urls: string[]; ips: string[] }
  obfuscation: { base64_candidates_count: number; xor_decoded: { key: string; decoded: string }[] }
  suspicious_imports: { category: string; api: string; address: string }[]
  sections: { name: string; size: number; entropy: number; is_highly_entropic: boolean }[]
  packer_info: { is_packed: boolean; suspicious_sections: string[]; suspected_packer: string }
  evasion_info: {
    uses_anti_debug: boolean
    anti_debug_apis_found: string[]
    uses_anti_vm: boolean
    anti_vm_strings_found: string[]
  }
  capabilities: { technique_id: string; tactic: string; description: string; evidence: string[] }[]
  top_suspicious_functions: {
    name: string
    address: string
    suspicion_score: number
    reasons: string[]
    instruction_count: number
    called_by: string[]
  }[]
  ioc_references: {
    string_value: string
    string_address: string
    ref_type: string
    ref_address: string
    referencing_function: string
  }[]
  threat_intel: {
    file_hash: string
    vt_positives: number
    vt_total: number
    malicious_ips: Record<string, number>
    yara_matches: { rule_name: string; description: string }[]
  }
}

export function getReport(fileHash: string) {
  return apiGet<AnalysisReport>(`/report/${encodeURIComponent(fileHash)}`)
}

export function getIocs(fileHash: string) {
  return apiGet<IocsResponse>(`/iocs/${encodeURIComponent(fileHash)}`)
}

