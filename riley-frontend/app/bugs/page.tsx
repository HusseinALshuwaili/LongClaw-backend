'use client'

import { useState } from 'react'

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10 border-red-400/30',
  high: 'text-orange-400 bg-orange-400/10 border-orange-400/30',
  medium: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
  low: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
}

const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-red-400',
  high: 'bg-orange-400',
  medium: 'bg-yellow-400',
  low: 'bg-blue-400',
}

type Finding = {
  id: string
  type: string
  severity: string
  cvss_score: number
  location: string
  code_snippet: string
  description: string
  attack_scenario: string
  suggested_fix: string
  debunker_confidence: number
  file_path: string
}

type ScanResult = {
  scan_id: string
  status: string
  input_type: string
  files_scanned: number
  model_used: string
  summary: { total_findings: number; critical?: number; high?: number; medium?: number; low?: number }
  findings: Finding[]
  error?: string
}

export default function BugsPage() {
  const [tab, setTab] = useState<'github' | 'paste'>('paste')
  const [githubUrl, setGithubUrl] = useState('')
  const [code, setCode] = useState('')
  const [language, setLanguage] = useState('python')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [phase, setPhase] = useState('')

  const PHASES = [
    'Analyzer scanning for suspicious patterns…',
    'Detector verifying exploitability…',
    'Debunker challenging findings…',
    'Consolidating results…',
  ]

  async function runScan() {
    setLoading(true)
    setResult(null)
    setExpanded(null)

    // Animate through phases
    let i = 0
    setPhase(PHASES[0])
    const interval = setInterval(() => {
      i = Math.min(i + 1, PHASES.length - 1)
      setPhase(PHASES[i])
    }, 4000)

    try {
      const endpoint = tab === 'github' ? '/api/v1/bugs/scan/github' : '/api/v1/bugs/scan/code'
      const body = tab === 'github'
        ? { github_url: githubUrl }
        : { code, language, filename: `snippet.${language}` }

      const resp = await fetch(`${API}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data: ScanResult = await resp.json()
      setResult(data)
    } catch {
      setResult({ scan_id: '', status: 'error', input_type: tab, files_scanned: 0, model_used: '', summary: { total_findings: 0 }, findings: [], error: 'Failed to reach Riley API' })
    } finally {
      clearInterval(interval)
      setLoading(false)
      setPhase('')
    }
  }

  const canSubmit = tab === 'github' ? githubUrl.trim().length > 10 : code.trim().length > 20

  return (
    <div className="p-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-1">
          <svg viewBox="0 0 20 20" fill="currentColor" className="w-5 h-5 text-accent">
            <path fillRule="evenodd" d="M12.316 3.051a1 1 0 01.633 1.265l-4 12a1 1 0 11-1.898-.632l4-12a1 1 0 011.265-.633zM5.707 6.293a1 1 0 010 1.414L3.414 10l2.293 2.293a1 1 0 11-1.414 1.414l-3-3a1 1 0 010-1.414l3-3a1 1 0 011.414 0zm8.586 0a1 1 0 011.414 0l3 3a1 1 0 010 1.414l-3 3a1 1 0 11-1.414-1.414L16.586 10l-2.293-2.293a1 1 0 010-1.414z" clipRule="evenodd" />
          </svg>
          <h1 className="text-xl font-semibold text-white">Bug Scanner</h1>
          <span className="px-2 py-0.5 text-[10px] bg-accent/10 text-accent border border-accent/20 rounded-full tracking-widest uppercase font-medium">
            3-Agent Pipeline
          </span>
        </div>
        <p className="text-sm text-white/40">
          Analyzer → Detector → Debunker. Only confirmed vulnerabilities surface.
        </p>
      </div>

      {/* Input card */}
      <div className="bg-[#0d0d1a] border border-white/[0.07] rounded-xl p-5 mb-6">
        {/* Tab switcher */}
        <div className="flex gap-1 mb-5 bg-white/[0.03] rounded-lg p-1 w-fit">
          {(['paste', 'github'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-all duration-150 ${
                tab === t
                  ? 'bg-accent/15 text-accent border border-accent/20'
                  : 'text-white/40 hover:text-white/60'
              }`}
            >
              {t === 'paste' ? 'Paste Code' : 'GitHub URL'}
            </button>
          ))}
        </div>

        {tab === 'paste' ? (
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <select
                value={language}
                onChange={(e) => setLanguage(e.target.value)}
                className="bg-white/[0.05] border border-white/[0.08] text-white/70 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent/40"
              >
                {['python', 'javascript', 'typescript', 'go', 'java', 'rust', 'php', 'ruby', 'c', 'cpp'].map((l) => (
                  <option key={l} value={l}>{l}</option>
                ))}
              </select>
              <span className="text-xs text-white/25">Select the code language</span>
            </div>
            <textarea
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder={`# Paste your code here\ndef get_user(user_id):\n    query = "SELECT * FROM users WHERE id=" + user_id\n    return db.execute(query)`}
              rows={14}
              className="w-full bg-[#08080f] border border-white/[0.07] rounded-lg px-4 py-3 text-sm text-white/80 font-mono placeholder:text-white/15 focus:outline-none focus:border-accent/30 resize-none"
            />
          </div>
        ) : (
          <div className="space-y-3">
            <input
              type="text"
              value={githubUrl}
              onChange={(e) => setGithubUrl(e.target.value)}
              placeholder="https://github.com/owner/repo"
              className="w-full bg-[#08080f] border border-white/[0.07] rounded-lg px-4 py-3 text-sm text-white/80 placeholder:text-white/20 focus:outline-none focus:border-accent/30"
            />
            <p className="text-xs text-white/25">
              Public repos only · Scans up to 12 source files · Python, JS, TS, Go, Java, Rust, PHP, Ruby, C/C++
            </p>
          </div>
        )}

        <div className="flex items-center justify-between mt-4">
          <p className="text-xs text-white/25">
            Powered by Groq · Llama 3.3 70B · 3-agent adversarial pipeline
          </p>
          <button
            onClick={runScan}
            disabled={loading || !canSubmit}
            className="flex items-center gap-2 px-5 py-2.5 bg-accent/20 hover:bg-accent/30 text-accent border border-accent/30 rounded-lg text-sm font-medium transition-all disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <span className="w-3.5 h-3.5 border border-accent/50 border-t-accent rounded-full animate-spin" />
                Scanning…
              </>
            ) : (
              <>
                <svg viewBox="0 0 20 20" fill="currentColor" className="w-4 h-4">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z" clipRule="evenodd" />
                </svg>
                Scan for Bugs
              </>
            )}
          </button>
        </div>
      </div>

      {/* Loading phase indicator */}
      {loading && phase && (
        <div className="flex items-center gap-3 bg-accent/5 border border-accent/15 rounded-lg px-4 py-3 mb-6">
          <span className="w-3.5 h-3.5 border border-accent/50 border-t-accent rounded-full animate-spin flex-shrink-0" />
          <span className="text-sm text-accent/80 font-mono">{phase}</span>
        </div>
      )}

      {/* Results */}
      {result && !loading && (
        <div>
          {result.error ? (
            <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-5 text-red-400 text-sm">
              {result.error}
            </div>
          ) : (
            <>
              {/* Summary bar */}
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-4">
                  <span className="text-white/60 text-sm">
                    <span className="text-white font-semibold">{result.summary.total_findings}</span> confirmed finding{result.summary.total_findings !== 1 ? 's' : ''}
                  </span>
                  <span className="text-white/25 text-xs">·</span>
                  <span className="text-white/40 text-xs">{result.files_scanned} file{result.files_scanned !== 1 ? 's' : ''} scanned</span>
                  {(['critical', 'high', 'medium', 'low'] as const).map((s) =>
                    result.summary[s] ? (
                      <span key={s} className={`px-2 py-0.5 text-xs border rounded-full ${SEVERITY_COLORS[s]}`}>
                        {result.summary[s]} {s}
                      </span>
                    ) : null
                  )}
                </div>
                <span className="text-xs text-white/20">{result.scan_id.slice(0, 8)}</span>
              </div>

              {result.findings.length === 0 ? (
                <div className="bg-green-500/5 border border-green-500/15 rounded-xl p-8 text-center">
                  <div className="w-10 h-10 bg-green-500/10 rounded-full flex items-center justify-center mx-auto mb-3">
                    <svg viewBox="0 0 20 20" fill="currentColor" className="w-5 h-5 text-green-400">
                      <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                    </svg>
                  </div>
                  <p className="text-green-400 font-medium">No confirmed vulnerabilities found</p>
                  <p className="text-white/30 text-sm mt-1">All patterns were either clean or debunked by the adversarial agent.</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {result.findings.map((f) => (
                    <div
                      key={f.id}
                      className="bg-[#0d0d1a] border border-white/[0.07] rounded-xl overflow-hidden"
                    >
                      {/* Finding header */}
                      <button
                        className="w-full flex items-center gap-4 px-5 py-4 hover:bg-white/[0.02] transition-colors text-left"
                        onClick={() => setExpanded(expanded === f.id ? null : f.id)}
                      >
                        <span className={`w-2 h-2 rounded-full flex-shrink-0 ${SEVERITY_DOT[f.severity] || 'bg-gray-400'}`} />
                        <span className={`px-2 py-0.5 text-xs border rounded-full flex-shrink-0 ${SEVERITY_COLORS[f.severity] || ''}`}>
                          {f.severity}
                        </span>
                        <span className="text-white/80 font-mono text-sm font-medium flex-1">
                          {f.type.replace(/_/g, ' ')}
                        </span>
                        {f.file_path && (
                          <span className="text-white/25 text-xs font-mono hidden md:block">
                            {f.file_path.split('/').slice(-2).join('/')}
                          </span>
                        )}
                        <span className="text-white/25 text-xs ml-2">CVSS {f.cvss_score.toFixed(1)}</span>
                        <svg
                          viewBox="0 0 20 20"
                          fill="currentColor"
                          className={`w-4 h-4 text-white/20 flex-shrink-0 transition-transform ${expanded === f.id ? 'rotate-180' : ''}`}
                        >
                          <path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd" />
                        </svg>
                      </button>

                      {/* Expanded detail */}
                      {expanded === f.id && (
                        <div className="px-5 pb-5 space-y-4 border-t border-white/[0.05]">
                          <div className="pt-4 grid md:grid-cols-2 gap-4">
                            {/* Left col */}
                            <div className="space-y-4">
                              <div>
                                <p className="text-[10px] text-white/30 uppercase tracking-widest mb-1.5">Description</p>
                                <p className="text-sm text-white/70 leading-relaxed">{f.description}</p>
                              </div>
                              <div>
                                <p className="text-[10px] text-white/30 uppercase tracking-widest mb-1.5">Attack Scenario</p>
                                <p className="text-sm text-orange-400/80 leading-relaxed">{f.attack_scenario}</p>
                              </div>
                              <div>
                                <p className="text-[10px] text-white/30 uppercase tracking-widest mb-1.5">Location</p>
                                <p className="text-xs text-white/40 font-mono">{f.location}</p>
                              </div>
                            </div>
                            {/* Right col */}
                            <div className="space-y-4">
                              <div>
                                <p className="text-[10px] text-white/30 uppercase tracking-widest mb-1.5">Vulnerable Code</p>
                                <pre className="bg-[#08080f] border border-red-500/10 rounded-lg p-3 text-xs text-red-300/80 font-mono overflow-x-auto whitespace-pre-wrap">
                                  {f.code_snippet}
                                </pre>
                              </div>
                              <div>
                                <p className="text-[10px] text-white/30 uppercase tracking-widest mb-1.5">Suggested Fix</p>
                                <pre className="bg-[#08080f] border border-green-500/10 rounded-lg p-3 text-xs text-green-300/80 font-mono overflow-x-auto whitespace-pre-wrap">
                                  {f.suggested_fix}
                                </pre>
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-2 pt-2 border-t border-white/[0.04]">
                            <span className="text-[10px] text-white/20">
                              Debunker confidence: {(f.debunker_confidence * 100).toFixed(0)}% this finding is real
                            </span>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}
