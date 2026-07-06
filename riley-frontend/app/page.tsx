'use client'

import { useEffect, useRef, useState } from 'react'
import Image from 'next/image'
import Link from 'next/link'
import {
  Zap, Activity, Brain, Check, X, ArrowRight, ChevronRight,
  Lock, Cloud, Globe, AlertTriangle, Workflow, Menu, Shield,
  ChevronLeft, Star, TrendingDown, Clock, Users, BarChart3,
} from 'lucide-react'
import { useInView } from '@/hooks/useInView'
import { useCounter } from '@/hooks/useCounter'
import WaitlistModal from '@/components/WaitlistModal'

// ─── Scroll-animated counter ─────────────────────────────────────────────────
function AnimatedStat({
  value, suffix = '', prefix = '', label, decimals = 0,
}: {
  value: number; suffix?: string; prefix?: string; label: string; decimals?: number
}) {
  const { ref, inView } = useInView({ threshold: 0.3 })
  const count = useCounter(value, inView, 1800, decimals)
  return (
    <div ref={ref as React.RefObject<HTMLDivElement>}
      className="bg-white p-10 flex flex-col justify-center border-r border-b border-black/10 last:border-r-0">
      <p className="text-5xl font-bold font-mono tracking-tighter mb-3 transition-all duration-300">
        {prefix}{decimals > 0 ? count.toFixed(decimals) : Math.round(count).toLocaleString()}{suffix}
      </p>
      <p className="text-xs uppercase tracking-widest font-bold opacity-60">{label}</p>
    </div>
  )
}

// ─── Live alert ticker ───────────────────────────────────────────────────────
const TICKER_ITEMS = [
  { verdict: 'FP', msg: 'PowerShell scheduled task', host: 'NYC-WS-0042', ms: 312 },
  { verdict: 'TP', msg: 'Lateral movement detected → escalated', host: 'LON-SRV-0017', ms: 840 },
  { verdict: 'FP', msg: 'Chrome auto-update flagged', host: 'SFO-WS-0391', ms: 201 },
  { verdict: 'FP', msg: 'Known admin tool execution', host: 'TKY-WS-0088', ms: 398 },
  { verdict: 'TP', msg: 'C2 beacon pattern → L2 escalation', host: 'BER-SRV-0003', ms: 1100 },
  { verdict: 'FP', msg: 'Nightly backup job triggered alert', host: 'SYD-WS-0204', ms: 275 },
  { verdict: 'FP', msg: 'LSASS memory read by Defender', host: 'AMS-WS-0059', ms: 189 },
  { verdict: 'FP', msg: 'DNS lookup to internal resolver', host: 'SGP-WS-0113', ms: 244 },
  { verdict: 'TP', msg: 'Credential dump attempt detected', host: 'DFW-SRV-0007', ms: 920 },
  { verdict: 'FP', msg: 'Office macro on whitelisted doc', host: 'CHI-WS-0378', ms: 331 },
]

function LiveAlertTicker() {
  const doubled = [...TICKER_ITEMS, ...TICKER_ITEMS]
  return (
    <div className="border-y border-white/10 bg-[#050505] py-4 overflow-hidden relative">
      <div className="absolute left-0 top-0 bottom-0 w-20 bg-gradient-to-r from-[#050505] to-transparent z-10" />
      <div className="absolute right-0 top-0 bottom-0 w-20 bg-gradient-to-l from-[#050505] to-transparent z-10" />
      <div
        className="flex gap-6 whitespace-nowrap"
        style={{ animation: 'ticker 40s linear infinite' }}
      >
        {doubled.map((item, i) => (
          <div key={i} className="flex items-center gap-3 shrink-0">
            <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 ${
              item.verdict === 'FP'
                ? 'bg-white/10 text-white/50'
                : 'bg-white/20 text-white'
            }`}>
              {item.verdict}
            </span>
            <span className="text-[11px] text-white/40 font-mono">{item.host}</span>
            <span className="text-[11px] text-white/25 font-sans font-light">{item.msg}</span>
            <span className="text-[9px] text-white/20 font-mono">{item.ms}ms</span>
            <span className="w-px h-4 bg-white/10 mx-2" />
          </div>
        ))}
      </div>
      <style>{`@keyframes ticker { from { transform: translateX(0) } to { transform: translateX(-50%) } }`}</style>
    </div>
  )
}

// ─── Customer logo bar ───────────────────────────────────────────────────────
const CUSTOMER_LOGOS = [
  'Apex FinTech', 'Vertex Health', 'Orion Energy', 'Summit Logistics',
  'Cascade Capital', 'Meridian Labs', 'Nexus Retail', 'Atlas Insurance',
]

function CustomerLogoBar() {
  return (
    <div className="py-16 bg-black border-b border-white/10">
      <div className="container mx-auto px-6 text-center">
        <p className="text-[10px] uppercase tracking-[0.3em] text-white/25 font-mono mb-10">
          Trusted by security teams at
        </p>
        <div className="flex flex-wrap items-center justify-center gap-x-12 gap-y-6">
          {CUSTOMER_LOGOS.map((name) => (
            <span
              key={name}
              className="text-xs uppercase tracking-widest text-white/25 hover:text-white/60 transition-colors font-mono cursor-default"
            >
              {name}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Comparison table ────────────────────────────────────────────────────────
const COMPARE_ROWS = [
  { feature: 'Sub-second alert triage',       riley: true,  manual: false, legacy: false },
  { feature: 'Continuous self-learning',       riley: true,  manual: false, legacy: false },
  { feature: 'Context-aware scoring',          riley: true,  manual: false, legacy: false },
  { feature: 'Natural language verdicts',      riley: true,  manual: true,  legacy: false },
  { feature: 'Zero new infrastructure',        riley: true,  manual: true,  legacy: false },
  { feature: 'Auto-escalation to L2/L3',      riley: true,  manual: false, legacy: false },
  { feature: '24 / 7 coverage',                riley: true,  manual: false, legacy: true  },
  { feature: 'False-positive reduction > 85%', riley: true,  manual: false, legacy: false },
  { feature: 'Analyst burnout',                riley: false, manual: true,  legacy: true  },
]

function ComparisonTable() {
  return (
    <section className="py-32 bg-[#050505] border-y border-white/10">
      <div className="container mx-auto px-6">
        <div className="max-w-3xl mb-16">
          <span className="text-[10px] uppercase tracking-[0.2em] text-white/30 font-mono">
            Why Riley
          </span>
          <h2 className="text-4xl md:text-5xl font-bold tracking-tighter text-white uppercase font-sans mt-3">
            Not all triage is equal.
          </h2>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-white/10">
                <th className="pb-6 text-[10px] uppercase tracking-widest text-white/30 font-mono w-1/2">
                  Capability
                </th>
                <th className="pb-6 text-[10px] uppercase tracking-widest text-center font-mono">
                  <span className="text-white border border-white px-3 py-1">Riley</span>
                </th>
                <th className="pb-6 text-[10px] uppercase tracking-widest text-white/30 text-center font-mono">
                  Manual Triage
                </th>
                <th className="pb-6 text-[10px] uppercase tracking-widest text-white/30 text-center font-mono">
                  Legacy SIEM Rules
                </th>
              </tr>
            </thead>
            <tbody>
              {COMPARE_ROWS.map((row, i) => (
                <tr key={i} className="border-b border-white/5 hover:bg-white/[0.02] transition-colors">
                  <td className="py-4 text-sm text-white/70 font-sans font-light">{row.feature}</td>
                  <td className="py-4 text-center">
                    {row.riley
                      ? <Check className="w-4 h-4 text-white mx-auto" />
                      : <X className="w-4 h-4 text-white/20 mx-auto" />}
                  </td>
                  <td className="py-4 text-center">
                    {row.manual
                      ? <Check className="w-4 h-4 text-white/40 mx-auto" />
                      : <X className="w-4 h-4 text-white/15 mx-auto" />}
                  </td>
                  <td className="py-4 text-center">
                    {row.legacy
                      ? <Check className="w-4 h-4 text-white/40 mx-auto" />
                      : <X className="w-4 h-4 text-white/15 mx-auto" />}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  )
}

// ─── Trust badges ────────────────────────────────────────────────────────────
const TRUST_BADGES = [
  { label: 'SOC 2 Type II', sub: 'In progress' },
  { label: 'ISO 27001',     sub: 'Aligned' },
  { label: 'GDPR',          sub: 'Compliant' },
  { label: 'CCPA',          sub: 'Compliant' },
  { label: 'End-to-End',    sub: 'Encrypted' },
  { label: 'Zero-Log',      sub: 'Architecture' },
]

function TrustBadges() {
  return (
    <div className="py-16 bg-black border-b border-white/10">
      <div className="container mx-auto px-6 text-center">
        <p className="text-[10px] uppercase tracking-[0.3em] text-white/25 font-mono mb-10">
          Security &amp; Compliance
        </p>
        <div className="flex flex-wrap items-center justify-center gap-4">
          {TRUST_BADGES.map(({ label, sub }) => (
            <div
              key={label}
              className="border border-white/10 px-6 py-3 flex flex-col items-center gap-1 hover:border-white/30 transition-colors"
            >
              <Shield className="w-4 h-4 text-white/30 mb-1" />
              <span className="text-[11px] font-mono font-bold text-white/70 uppercase tracking-wider">
                {label}
              </span>
              <span className="text-[9px] font-mono text-white/25 uppercase tracking-widest">
                {sub}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Multi-testimonial carousel ──────────────────────────────────────────────
const TESTIMONIALS = [
  {
    quote: "Before Riley, our SOC analysts were basically human regex parsers. Now they actually hunt. Employee retention is up, and our MTTR dropped 60%. First security tool that actually delivered.",
    name: 'Sarah Jenkins',
    title: 'Dir. Security Ops',
    company: 'FinTech Corp',
    initials: 'SJ',
    metric: '60% MTTR drop',
  },
  {
    quote: "We were closing 400 false positives a day manually. Riley handles 380 of them automatically. My team went from exhausted to engaged in two weeks. I wish we'd found this sooner.",
    name: 'Marcus Okonkwo',
    title: 'CISO',
    company: 'Apex Health Systems',
    initials: 'MO',
    metric: '380 FPs/day automated',
  },
  {
    quote: "The ROI was immediate. We calculated $180K in analyst time recovered in the first quarter alone. The AI verdicts are explainable, which matters for our compliance team.",
    name: 'Priya Nair',
    title: 'VP Security Engineering',
    company: 'Cascade Capital',
    initials: 'PN',
    metric: '$180K saved Q1',
  },
]

function TestimonialCarousel() {
  const [idx, setIdx] = useState(0)
  const prev = () => setIdx((i) => (i - 1 + TESTIMONIALS.length) % TESTIMONIALS.length)
  const next = () => setIdx((i) => (i + 1) % TESTIMONIALS.length)

  return (
    <section className="py-32 relative bg-black border-b border-white/10 overflow-hidden">
      <div className="container mx-auto px-6">
        <div className="text-center mb-16">
          <span className="text-[10px] uppercase tracking-[0.2em] text-white/30 font-mono">
            Customer Stories
          </span>
          <h2 className="text-3xl font-bold tracking-tighter text-white uppercase font-sans mt-3">
            Real teams. Real results.
          </h2>
        </div>

        {/* Cards - desktop: 3 up, mobile: carousel */}
        <div className="hidden md:grid md:grid-cols-3 gap-6">
          {TESTIMONIALS.map((t, i) => (
            <div key={i} className="border border-white/10 p-8 hover:border-white/30 transition-colors flex flex-col">
              <div className="flex gap-1 mb-6">
                {[...Array(5)].map((_, s) => (
                  <Star key={s} className="w-3 h-3 text-white fill-white" />
                ))}
              </div>
              <p className="text-white/60 font-light leading-relaxed font-sans text-sm flex-1 mb-8">
                &ldquo;{t.quote}&rdquo;
              </p>
              <div className="pt-6 border-t border-white/10 flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 border border-white/30 flex items-center justify-center text-xs font-bold text-white shrink-0">
                    {t.initials}
                  </div>
                  <div>
                    <p className="text-white font-bold text-xs uppercase tracking-wider">{t.name}</p>
                    <p className="text-white/30 text-[10px] uppercase tracking-widest">{t.title}, {t.company}</p>
                  </div>
                </div>
                <span className="text-[9px] font-mono text-white/40 border border-white/10 px-2 py-1 whitespace-nowrap">
                  {t.metric}
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* Mobile carousel */}
        <div className="md:hidden">
          <div className="border border-white/10 p-8">
            <div className="flex gap-1 mb-6">
              {[...Array(5)].map((_, s) => (
                <Star key={s} className="w-3 h-3 text-white fill-white" />
              ))}
            </div>
            <p className="text-white/60 font-light leading-relaxed font-sans text-sm mb-8">
              &ldquo;{TESTIMONIALS[idx].quote}&rdquo;
            </p>
            <div className="pt-6 border-t border-white/10 flex items-center gap-4">
              <div className="w-10 h-10 border border-white/30 flex items-center justify-center text-xs font-bold text-white">
                {TESTIMONIALS[idx].initials}
              </div>
              <div>
                <p className="text-white font-bold text-xs uppercase tracking-wider">{TESTIMONIALS[idx].name}</p>
                <p className="text-white/30 text-[10px] uppercase tracking-widest">{TESTIMONIALS[idx].title}</p>
              </div>
            </div>
          </div>
          <div className="flex justify-center gap-4 mt-6">
            <button onClick={prev} className="border border-white/20 p-2 hover:bg-white/10 transition-colors">
              <ChevronLeft className="w-4 h-4 text-white" />
            </button>
            {TESTIMONIALS.map((_, i) => (
              <button
                key={i}
                onClick={() => setIdx(i)}
                className={`w-1.5 h-1.5 transition-colors ${i === idx ? 'bg-white' : 'bg-white/20'}`}
              />
            ))}
            <button onClick={next} className="border border-white/20 p-2 hover:bg-white/10 transition-colors">
              <ChevronRight className="w-4 h-4 text-white" />
            </button>
          </div>
        </div>
      </div>
    </section>
  )
}

// ─── Platform tabs showcase ──────────────────────────────────────────────────
const PLATFORM_TABS = [
  {
    id: 'queue',
    label: 'Alert Queue',
    icon: Activity,
    headline: 'Every alert, prioritized.',
    desc: 'Riley\'s queue shows your true positives at the top, false positives already resolved, and a confidence score on everything in between. No more triaging blindly.',
    img: '/ui-queue.png',
    stats: [
      { label: 'Alerts resolved automatically', value: '92%' },
      { label: 'Avg triage time', value: '0.4s' },
    ],
  },
  {
    id: 'verdict',
    label: 'Verdict Engine',
    icon: Brain,
    headline: 'Reasoning you can read.',
    desc: 'Every Riley verdict includes a plain-English explanation and a chain of evidence. Agree or disagree with one click — she updates her model within 24 hours.',
    img: '/ui-queue.png',
    stats: [
      { label: 'Verdict accuracy', value: '94%' },
      { label: 'Evidence chains per verdict', value: '5–12' },
    ],
  },
  {
    id: 'bugs',
    label: 'Bug Scanner',
    icon: Shield,
    headline: 'Code-level threat detection.',
    desc: 'Paste code or drop a GitHub URL. Riley\'s 3-agent pipeline analyzes, detects, and debunks vulnerabilities — surfacing only real issues with full remediation guidance.',
    img: '/ui-queue.png',
    stats: [
      { label: 'Languages supported', value: '12+' },
      { label: 'False positives', value: '<8%' },
    ],
  },
]

function PlatformTabs() {
  const [active, setActive] = useState(0)
  const tab = PLATFORM_TABS[active]

  return (
    <section className="py-32 bg-black border-y border-white/10">
      <div className="container mx-auto px-6">
        <div className="text-center mb-16">
          <span className="text-[10px] uppercase tracking-[0.2em] text-white/30 font-mono">
            The Platform
          </span>
          <h2 className="text-4xl font-bold tracking-tighter text-white uppercase font-sans mt-3">
            See every layer.
          </h2>
        </div>

        {/* Tab buttons */}
        <div className="flex gap-px mb-px border border-white/10 w-fit mx-auto">
          {PLATFORM_TABS.map((t, i) => {
            const Icon = t.icon
            return (
              <button
                key={t.id}
                onClick={() => setActive(i)}
                className={`flex items-center gap-2 px-6 py-3 text-xs uppercase tracking-widest transition-all ${
                  active === i
                    ? 'bg-white text-black font-bold'
                    : 'text-white/40 hover:text-white hover:bg-white/5'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                {t.label}
              </button>
            )
          })}
        </div>

        {/* Tab content */}
        <div className="border border-white/10 grid lg:grid-cols-5 gap-0">
          {/* Screenshot */}
          <div className="lg:col-span-3 border-b lg:border-b-0 lg:border-r border-white/10 bg-[#050505] relative overflow-hidden">
            <div className="h-8 bg-[#0a0a0a] border-b border-white/10 flex items-center px-4 gap-2">
              <div className="w-2 h-2 bg-white/20" />
              <div className="w-2 h-2 bg-white/20" />
              <div className="w-2 h-2 bg-white/20" />
              <span className="text-[9px] text-white/20 font-mono ml-2 uppercase tracking-widest">
                riley-security.io / {tab.id}
              </span>
            </div>
            <Image
              src={tab.img}
              alt={tab.label}
              width={700}
              height={450}
              className="w-full h-auto filter grayscale contrast-125 opacity-80"
            />
          </div>

          {/* Description */}
          <div className="lg:col-span-2 p-10 flex flex-col justify-center">
            <h3 className="text-2xl font-bold text-white uppercase tracking-tight font-sans mb-4">
              {tab.headline}
            </h3>
            <p className="text-white/50 font-light leading-relaxed font-sans mb-8 text-sm">
              {tab.desc}
            </p>
            <div className="space-y-4">
              {tab.stats.map((s, i) => (
                <div key={i} className="flex items-center justify-between border-b border-white/5 pb-4">
                  <span className="text-[11px] uppercase tracking-widest text-white/30 font-mono">
                    {s.label}
                  </span>
                  <span className="text-lg font-bold font-mono text-white">{s.value}</span>
                </div>
              ))}
            </div>
            <Link
              href="https://riley-dashboard-riley-dashboard.vercel.app"
              className="mt-8 flex items-center gap-2 text-xs uppercase tracking-widest text-white/40 hover:text-white transition-colors group"
            >
              Try it live <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
            </Link>
          </div>
        </div>
      </div>
    </section>
  )
}

// ─── Rotating greeting banner ────────────────────────────────────────────────
const GREETINGS = [
  "There is only one war that matters: The war against inefficiency. Let us win it together, Your Grace. How can I assist?",
  "I am the watcher on the walls of your enterprise. Speak, and I shall unmask the truth for you. What requires your attention?",
]

function GreetingBanner() {
  const [idx, setIdx] = useState(() => Math.floor(Math.random() * GREETINGS.length))
  const [visible, setVisible] = useState(true)

  useEffect(() => {
    const interval = setInterval(() => {
      setVisible(false)
      setTimeout(() => { setIdx((i) => (i + 1) % GREETINGS.length); setVisible(true) }, 500)
    }, 7000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="border-b border-white/10 bg-white/[0.03] backdrop-blur-sm overflow-hidden">
      <div className="container mx-auto px-6 py-3 flex items-center gap-4">
        <div className="flex-shrink-0 flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />
          <span className="text-[9px] font-mono text-white/30 uppercase tracking-[0.2em]">Riley</span>
        </div>
        <div className="h-3 w-px bg-white/10" />
        <p className="text-[11px] text-white/50 font-mono tracking-wide transition-opacity duration-500 truncate"
          style={{ opacity: visible ? 1 : 0 }}>
          {GREETINGS[idx]}
        </p>
      </div>
    </div>
  )
}

// ─── ROI Calculator ───────────────────────────────────────────────────────────
function RoiCalculator() {
  const [analysts, setAnalysts] = useState(5)
  const [alertsPerDay, setAlertsPerDay] = useState(500)

  const alertsPerMonth = alertsPerDay * 22
  const fpRate = 0.87
  const minutesPerFP = 4
  const hourlyRate = 95

  const hoursWasted = Math.round((alertsPerMonth * fpRate * minutesPerFP) / 60)
  const dollarsSaved = Math.round(hoursWasted * hourlyRate * analysts)
  const daysBack = Math.round(hoursWasted / 8)

  return (
    <section className="py-24 bg-[#050505] border-y border-white/10">
      <div className="container mx-auto px-6 max-w-5xl">
        <div className="text-center mb-14">
          <span className="text-[10px] font-mono text-white/30 uppercase tracking-[0.2em]">ROI Calculator</span>
          <h2 className="text-3xl md:text-4xl font-bold text-white tracking-tighter uppercase mt-3">
            What is alert fatigue actually costing you?
          </h2>
        </div>

        <div className="grid lg:grid-cols-2 gap-12 items-center">
          <div className="space-y-10">
            <div>
              <div className="flex justify-between items-center mb-3">
                <label className="text-xs font-mono text-white/50 uppercase tracking-widest">Security analysts</label>
                <span className="text-white font-mono font-bold text-lg">{analysts}</span>
              </div>
              <input type="range" min={1} max={50} value={analysts}
                onChange={(e) => setAnalysts(+e.target.value)}
                className="w-full h-0.5 bg-white/10 appearance-none [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-4 [&::-webkit-slider-thumb]:h-4 [&::-webkit-slider-thumb]:bg-white [&::-webkit-slider-thumb]:cursor-pointer" />
              <div className="flex justify-between text-[10px] text-white/20 font-mono mt-1"><span>1</span><span>50</span></div>
            </div>
            <div>
              <div className="flex justify-between items-center mb-3">
                <label className="text-xs font-mono text-white/50 uppercase tracking-widest">Alerts per day</label>
                <span className="text-white font-mono font-bold text-lg">{alertsPerDay.toLocaleString()}</span>
              </div>
              <input type="range" min={50} max={5000} step={50} value={alertsPerDay}
                onChange={(e) => setAlertsPerDay(+e.target.value)}
                className="w-full h-0.5 bg-white/10 appearance-none [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-4 [&::-webkit-slider-thumb]:h-4 [&::-webkit-slider-thumb]:bg-white [&::-webkit-slider-thumb]:cursor-pointer" />
              <div className="flex justify-between text-[10px] text-white/20 font-mono mt-1"><span>50</span><span>5,000</span></div>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-px bg-white/10">
            <div className="bg-[#050505] p-8 flex flex-col justify-center">
              <p className="text-3xl font-bold font-mono text-white tracking-tighter">{hoursWasted.toLocaleString()}</p>
              <p className="text-[10px] uppercase tracking-widest text-white/35 font-mono mt-2">Analyst hrs wasted / mo</p>
            </div>
            <div className="bg-[#050505] p-8 flex flex-col justify-center">
              <p className="text-3xl font-bold font-mono text-white tracking-tighter">{daysBack}</p>
              <p className="text-[10px] uppercase tracking-widest text-white/35 font-mono mt-2">Work days lost / mo</p>
            </div>
            <div className="bg-[#050505] p-8 flex flex-col justify-center border border-white/20">
              <p className="text-3xl font-bold font-mono text-white tracking-tighter">${(dollarsSaved / 1000).toFixed(0)}K</p>
              <p className="text-[10px] uppercase tracking-widest text-white/35 font-mono mt-2">Monthly cost savings</p>
            </div>
          </div>
        </div>
        <p className="text-center text-white/20 text-[10px] font-mono mt-8 uppercase tracking-widest">
          Assumes 87% FP rate · 4 min per investigation · $95/hr blended analyst cost
        </p>
      </div>
    </section>
  )
}

// ─── Main Landing Page ────────────────────────────────────────────────────────
export default function LandingPage() {
  const [modalOpen, setModalOpen] = useState(false)
  const [modalSource, setModalSource] = useState('Early Access')
  const [mobileMenu, setMobileMenu] = useState(false)

  const openModal = (source: string) => { setModalSource(source); setModalOpen(true) }

  return (
    <div className="min-h-screen bg-black text-white overflow-x-hidden font-mono selection:bg-white selection:text-black">
      {/* Grid background */}
      <div className="fixed inset-0 pointer-events-none opacity-30" style={{
        backgroundImage: 'linear-gradient(to right, rgba(255,255,255,0.03) 1px, transparent 1px), linear-gradient(to bottom, rgba(255,255,255,0.03) 1px, transparent 1px)',
        backgroundSize: '4rem 4rem',
      }} />

      {/* NAVBAR */}
      <nav className="fixed top-0 left-0 right-0 z-50 border-b border-white/10 bg-black/90 backdrop-blur-md">
        <div className="container mx-auto px-6 h-20 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Image src="/riley-logo.png" alt="Riley" width={32} height={32} className="h-8 w-auto object-contain" />
            <span className="text-xl tracking-[0.2em] font-light text-white uppercase hidden sm:inline-block">Riley</span>
          </div>
          <div className="hidden md:flex items-center gap-8 text-xs tracking-widest text-white/40 uppercase">
            <a href="#platform" className="hover:text-white transition-colors">Platform</a>
            <a href="#compare" className="hover:text-white transition-colors">Compare</a>
            <a href="#integrations" className="hover:text-white transition-colors">Integrations</a>
            <a href="#roi" className="hover:text-white transition-colors">ROI</a>
          </div>
          <div className="flex items-center gap-3">
            <Link href="https://riley-dashboard-riley-dashboard.vercel.app" className="hidden md:inline-flex text-xs uppercase tracking-widest border border-white/20 px-4 py-2 text-white/70 hover:bg-white hover:text-black transition-all">
              Live Demo
            </Link>
            <button onClick={() => openModal('Hire Riley')}
              className="text-xs uppercase tracking-widest bg-white text-black px-4 py-2 hover:bg-gray-200 transition-all font-bold">
              Hire Riley
            </button>
            <button className="md:hidden text-white/60 hover:text-white" onClick={() => setMobileMenu((v) => !v)}>
              <Menu className="w-5 h-5" />
            </button>
          </div>
        </div>
        {mobileMenu && (
          <div className="md:hidden border-t border-white/10 bg-black px-6 py-4 space-y-3">
            {['Platform', 'Compare', 'Integrations', 'ROI'].map((item) => (
              <a key={item} href={`#${item.toLowerCase()}`} onClick={() => setMobileMenu(false)}
                className="block text-xs uppercase tracking-widest text-white/50 hover:text-white py-2">{item}</a>
            ))}
          </div>
        )}
      </nav>

      <main className="pt-20">
        <GreetingBanner />

        {/* ── HERO ─────────────────────────────────────────────────────────── */}
        <section className="relative min-h-[90vh] flex items-center pt-12 pb-24 lg:pt-0 overflow-hidden">
          <div className="container mx-auto px-6 relative z-10">
            <div className="grid lg:grid-cols-2 gap-16 items-center">
              <div className="max-w-2xl">
                <div className="inline-flex items-center gap-3 border border-white/20 bg-white/5 px-4 py-1.5 mb-8">
                  <span className="w-1.5 h-1.5 bg-white animate-pulse inline-block" />
                  <span className="text-xs uppercase tracking-widest text-white">Beta Access Open</span>
                </div>
                <h1 className="text-6xl sm:text-7xl lg:text-8xl font-bold tracking-tighter leading-[1.05] mb-8 text-white">
                  Stop triaging{' '}
                  <span className="border-b-4 border-white pb-1">noise.</span>{' '}
                  Hunt real threats.
                </h1>
                <p className="text-xl text-white/50 mb-10 font-light leading-relaxed tracking-wide font-sans">
                  Your SOC gets 2,000 alerts a day. Riley auto-resolves 1,840 of them — learning your
                  environment, scoring every alert in seconds, and surfacing only the 160 that genuinely
                  need a human.
                </p>
                <div className="flex flex-col sm:flex-row gap-4">
                  <button onClick={() => openModal('Deploy Riley')}
                    className="h-14 px-8 text-sm uppercase tracking-widest font-bold bg-white text-black hover:bg-gray-200 transition-all border border-white flex items-center justify-center gap-3">
                    Deploy Riley <ArrowRight className="w-4 h-4" />
                  </button>
                  <Link href="https://riley-dashboard-riley-dashboard.vercel.app"
                    className="h-14 px-8 text-sm uppercase tracking-widest border border-white/20 hover:bg-white/10 transition-all flex items-center justify-center gap-3 text-white/70 hover:text-white">
                    Try the Dashboard
                  </Link>
                </div>
              </div>

              <div className="relative">
                <div className="relative overflow-hidden border border-white/20 bg-black p-2">
                  <div className="absolute top-0 left-0 w-4 h-4 border-t border-l border-white" />
                  <div className="absolute top-0 right-0 w-4 h-4 border-t border-r border-white" />
                  <div className="absolute bottom-0 left-0 w-4 h-4 border-b border-l border-white" />
                  <div className="absolute bottom-0 right-0 w-4 h-4 border-b border-r border-white" />
                  <Image src="/riley-mascot.png" alt="Riley AI Mascot" width={600} height={600}
                    className="w-full h-auto object-cover aspect-square filter grayscale contrast-125" />
                  <div className="absolute bottom-6 left-6 right-6 bg-black border border-white/20 p-4 flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="w-10 h-10 border border-white/20 flex items-center justify-center">
                        <Activity className="w-5 h-5 text-white" />
                      </div>
                      <div>
                        <p className="text-sm font-bold text-white uppercase tracking-wider">Alerts Processed</p>
                        <p className="text-xs text-white/40 uppercase tracking-widest mt-1">Last 24 hours</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-2xl font-bold text-white tracking-tighter">14,208</p>
                      <p className="text-xs text-white/40 mt-1">−92% noise</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ── LIVE ALERT TICKER ─────────────────────────────────────────────── */}
        <LiveAlertTicker />

        {/* ── CUSTOMER LOGOS ────────────────────────────────────────────────── */}
        <CustomerLogoBar />

        {/* ── THE PROBLEM ──────────────────────────────────────────────────── */}
        <section className="py-32 bg-black relative border-y border-white/10">
          <div className="container mx-auto px-6">
            <div className="max-w-4xl mx-auto text-center mb-24">
              <h2 className="text-4xl md:text-5xl font-bold tracking-tighter text-white mb-6 uppercase font-sans">
                Your team is drowning in alerts.{' '}
                <span className="text-white/40 font-light">Your attackers know it.</span>
              </h2>
              <p className="text-lg text-white/50 font-light tracking-wide font-sans">
                L1 analysts spend 80% of their shift closing benign alerts — the same false positives,
                every shift, forever. When everything screams critical, real attacks hide in the noise.
                Riley kills the noise at the source so your team can focus on what matters.
              </p>
            </div>
            <div className="grid md:grid-cols-3 gap-8">
              {[
                { icon: Brain, title: 'Context-Aware', desc: 'Riley looks at historical triage data, user context, and asset criticality — not just static rules.' },
                { icon: Zap, title: 'Lightning Fast', desc: 'Alerts are analyzed, enriched, and tagged within 400ms of hitting your SIEM. No query lag.' },
                { icon: Lock, title: 'Non-Destructive', desc: 'She sits next to your tools, not in front of them. Riley downgrades and tags; she never deletes data.' },
              ].map(({ icon: Icon, title, desc }, i) => (
                <div key={i} className="group p-8 bg-black border border-white/10 hover:border-white/40 transition-colors duration-300 relative">
                  <div className="absolute top-0 right-0 w-8 h-8 border-t border-r border-transparent group-hover:border-white transition-colors duration-300" />
                  <div className="w-12 h-12 border border-white/20 flex items-center justify-center mb-8 group-hover:bg-white group-hover:border-white transition-all duration-300">
                    <Icon className="w-5 h-5 text-white group-hover:text-black transition-colors" />
                  </div>
                  <h3 className="text-lg font-bold text-white mb-4 uppercase tracking-widest">{title}</h3>
                  <p className="text-white/50 font-light leading-relaxed font-sans">{desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── PLATFORM TABS ─────────────────────────────────────────────────── */}
        <div id="platform"><PlatformTabs /></div>

        {/* ── HOW IT WORKS ─────────────────────────────────────────────────── */}
        <section id="how-it-works" className="py-32 relative overflow-hidden bg-[#050505]">
          <div className="container mx-auto px-6 relative z-10">
            <div className="grid lg:grid-cols-2 gap-20 items-center">
              <div className="relative group">
                <div className="relative border border-white/20 bg-black">
                  <div className="h-10 bg-[#0a0a0a] border-b border-white/20 flex items-center px-4 justify-between">
                    <div className="flex gap-2">
                      <div className="w-2 h-2 bg-white/20" /><div className="w-2 h-2 bg-white/20" /><div className="w-2 h-2 bg-white/20" />
                    </div>
                    <div className="text-[10px] text-white/30 uppercase tracking-widest">riley-triage-queue.local</div>
                  </div>
                  <Image src="/ui-queue.png" alt="Riley UI Queue" width={700} height={450}
                    className="w-full h-auto filter grayscale contrast-125" />
                  <div className="absolute bottom-8 right-8 bg-black border border-white p-5 shadow-2xl">
                    <p className="text-xs uppercase tracking-widest font-bold text-white mb-4">Is this assessment correct?</p>
                    <div className="flex gap-3">
                      <button className="flex items-center gap-1.5 bg-white text-black px-3 py-2 text-[10px] uppercase tracking-widest font-bold hover:bg-gray-200 transition-colors">
                        <Check className="w-3 h-3" /> Agree
                      </button>
                      <button className="flex items-center gap-1.5 border border-white/20 px-3 py-2 text-[10px] uppercase tracking-widest font-bold hover:bg-white/10 transition-colors">
                        <X className="w-3 h-3" /> Disagree
                      </button>
                    </div>
                  </div>
                </div>
              </div>
              <div>
                <span className="text-[10px] uppercase tracking-[0.2em] text-white/30 border border-white/20 px-3 py-1 inline-block mb-8">
                  Continuous Learning
                </span>
                <h2 className="text-4xl md:text-5xl font-bold tracking-tighter text-white mb-8 uppercase font-sans">
                  Train her with a single click.
                </h2>
                <p className="text-lg text-white/50 font-light mb-10 leading-relaxed font-sans">
                  Riley explains every decision in plain English. Hit <strong className="text-white">Agree</strong> to
                  reinforce. Hit <strong className="text-white">Disagree</strong> and tell her why. She updates her
                  confidence model within 24 hours.
                </p>
                <div className="space-y-5">
                  {[
                    'Reads execution arguments and compares to baselines',
                    'Checks parent/child process trees for anomalies',
                    'Queries threat intelligence feeds automatically',
                    'Updates confidence scoring every 24 hours',
                  ].map((item, i) => (
                    <div key={i} className="flex items-start gap-4">
                      <div className="mt-1 w-5 h-5 border border-white/30 flex items-center justify-center shrink-0">
                        <Check className="w-3 h-3 text-white" />
                      </div>
                      <p className="text-white/70 font-light font-sans">{item}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ── FEATURES ─────────────────────────────────────────────────────── */}
        <section id="features" className="py-32 bg-black relative border-y border-white/10">
          <div className="container mx-auto px-6">
            <div className="max-w-3xl mb-20">
              <h2 className="text-4xl md:text-5xl font-bold tracking-tighter text-white mb-6 uppercase font-sans">
                Built for the reality of modern security.
              </h2>
              <p className="text-lg text-white/50 font-light tracking-wide font-sans">
                We didn&apos;t build a toy. Riley is engineered for enterprise alert volume, designed by people who have actually carried a pager.
              </p>
            </div>
            <div className="grid md:grid-cols-2 gap-x-16 gap-y-16">
              {[
                { icon: Workflow, title: 'Automated Playbooks', desc: 'Trigger containment actions for high-confidence true positives. Riley can isolate a host via EDR before an analyst even sees the ticket.' },
                { icon: AlertTriangle, title: 'Confidence Scoring', desc: 'Every assessment comes with a mathematically grounded confidence score. Set thresholds for auto-closing versus requiring human review.' },
                { icon: Cloud, title: 'Cloud-Native Scale', desc: '10 alerts a day or 10,000 — our infrastructure scales dynamically so your queue is always processed in milliseconds.' },
                { icon: Globe, title: 'Global Threat Intel', desc: 'Riley cross-references IOCs against leading global threat intelligence feeds to catch emerging campaigns before they escalate.' },
              ].map(({ icon: Icon, title, desc }, i) => (
                <div key={i} className="flex gap-6 group">
                  <div className="w-12 h-12 border border-white/20 flex items-center justify-center shrink-0 group-hover:border-white transition-colors">
                    <Icon className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <h3 className="text-lg font-bold text-white mb-3 uppercase tracking-widest">{title}</h3>
                    <p className="text-white/50 font-light leading-relaxed font-sans">{desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── COMPARISON TABLE ─────────────────────────────────────────────── */}
        <div id="compare"><ComparisonTable /></div>

        {/* ── INTEGRATIONS ─────────────────────────────────────────────────── */}
        <section id="integrations" className="py-32 relative bg-[#050505]">
          <div className="container mx-auto px-6 text-center">
            <h2 className="text-2xl md:text-3xl font-bold tracking-widest text-white mb-6 uppercase">
              System Integrations
            </h2>
            <p className="text-white/40 font-light mb-16 max-w-2xl mx-auto font-sans">
              No rip-and-replace required. Riley hooks directly into the APIs of the tools you already rely on.
            </p>
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4 opacity-60 hover:opacity-100 transition-opacity duration-500">
              {['Splunk', 'CrowdStrike', 'SentinelOne', 'Datadog', 'Jira', 'ServiceNow', 'Elastic', 'Microsoft Sentinel', 'PagerDuty', 'Slack', 'Okta', 'AWS'].map((tool) => (
                <div key={tool} className="h-16 flex items-center justify-center border border-white/10 bg-black hover:border-white/40 hover:text-white transition-all text-xs uppercase tracking-widest text-white/40">
                  {tool}
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── ROI METRICS ──────────────────────────────────────────────────── */}
        <section id="roi" className="py-32 bg-white text-black relative overflow-hidden">
          <div className="container mx-auto px-6 relative z-10">
            <div className="grid md:grid-cols-2 gap-16 items-center">
              <div>
                <h2 className="text-4xl md:text-6xl font-bold tracking-tighter mb-8 uppercase font-sans text-black">
                  Get two workdays a month back.
                </h2>
                <p className="text-xl font-light opacity-70 mb-10 max-w-lg leading-relaxed tracking-wide font-sans">
                  Stop burning out your most expensive talent on tier-1 triage. Riley handles the volume so your humans can handle the complexity.
                </p>
                <button onClick={() => openModal('Calculate Savings')}
                  className="h-14 px-8 text-sm font-bold uppercase tracking-widest bg-black text-white hover:bg-gray-800 transition-all flex items-center gap-3">
                  Claim your time back <ChevronRight className="w-4 h-4" />
                </button>
              </div>
              <div className="grid grid-cols-2 border border-black/10">
                <AnimatedStat value={87} suffix="%" label="Reduction in noise" />
                <AnimatedStat value={400} suffix="ms" label="Triage latency" />
                <AnimatedStat value={0} label="New dashboards needed" />
                <div className="bg-white p-10 flex flex-col justify-center">
                  <p className="text-5xl font-bold font-mono tracking-tighter mb-3">24/7</p>
                  <p className="text-xs uppercase tracking-widest font-bold opacity-60">Coverage</p>
                </div>
              </div>
            </div>
          </div>
        </section>

        <RoiCalculator />

        {/* ── TRUST BADGES ─────────────────────────────────────────────────── */}
        <TrustBadges />

        {/* ── TESTIMONIALS ─────────────────────────────────────────────────── */}
        <TestimonialCarousel />

        {/* ── LIVE DEMO CTA ─────────────────────────────────────────────────── */}
        <section className="py-24 bg-[#050505] border-b border-white/10">
          <div className="container mx-auto px-6 text-center">
            <div className="max-w-2xl mx-auto">
              <span className="text-[10px] uppercase tracking-[0.2em] text-white/30 font-mono">No sign-up required</span>
              <h2 className="text-3xl md:text-4xl font-bold text-white uppercase tracking-tight mt-3 mb-6 font-sans">
                See Riley in action — right now.
              </h2>
              <p className="text-white/40 font-light mb-10 font-sans">
                The live dashboard is open. Submit a real alert, watch the pipeline score it, and submit your verdict. No account. No credit card. No waiting.
              </p>
              <Link href="https://riley-dashboard-riley-dashboard.vercel.app"
                className="inline-flex items-center gap-3 h-14 px-10 bg-white text-black text-sm font-bold uppercase tracking-widest hover:bg-gray-200 transition-all">
                Open the Dashboard <ArrowRight className="w-4 h-4" />
              </Link>
              <p className="text-white/20 text-xs uppercase tracking-widest mt-6 font-mono">
                Processes alerts in real time · Learn as you go
              </p>
            </div>
          </div>
        </section>

        {/* ── FINAL CTA ─────────────────────────────────────────────────────── */}
        <section className="py-32 relative bg-[#020205]">
          <div className="container mx-auto px-6 relative z-10 text-center">
            <div className="w-16 h-16 border border-white flex items-center justify-center mx-auto mb-10">
              <Lock className="w-6 h-6 text-white" />
            </div>
            <h2 className="text-5xl md:text-7xl font-bold tracking-tighter text-white mb-8 uppercase font-sans">
              Ready to meet your new teammate?
            </h2>
            <p className="text-xl text-white/40 font-light mb-12 max-w-2xl mx-auto tracking-wide font-sans">
              Deployment takes 15 minutes. Riley connects via API to your existing tools. No agents to install. No disruption to your workflow.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <button onClick={() => openModal('Book a Demo')}
                className="h-16 px-12 text-sm font-bold uppercase tracking-widest bg-white text-black hover:bg-gray-200 transition-all">
                Book a Demo
              </button>
              <Link href="https://riley-dashboard-riley-dashboard.vercel.app"
                className="h-16 px-12 text-sm font-bold uppercase tracking-widest border border-white/20 text-white/70 hover:border-white hover:text-white transition-all flex items-center justify-center gap-3">
                Try the Dashboard →
              </Link>
            </div>
            <p className="mt-10 text-xs text-white/20 uppercase tracking-widest">
              Supports Splunk · CrowdStrike · SentinelOne · MS Sentinel · and more
            </p>
          </div>
        </section>
      </main>

      {/* FOOTER */}
      <footer className="border-t border-white/10 bg-black py-12">
        <div className="container mx-auto px-6 flex flex-col md:flex-row justify-between items-center gap-8">
          <div className="flex items-center gap-4">
            <Image src="/riley-logo.png" alt="Riley" width={24} height={24} className="h-6 w-auto" />
            <span className="font-bold text-white tracking-widest uppercase text-sm">Riley Security Inc.</span>
          </div>
          <div className="flex gap-8 text-xs text-white/30 uppercase tracking-widest">
            <a href="#" className="hover:text-white transition-colors">Docs</a>
            <a href="#" className="hover:text-white transition-colors">Privacy</a>
            <a href="#" className="hover:text-white transition-colors">Terms</a>
            <Link href="https://riley-dashboard-riley-dashboard.vercel.app" className="hover:text-white transition-colors">Dashboard</Link>
          </div>
        </div>
      </footer>

      <WaitlistModal open={modalOpen} onOpenChange={setModalOpen} source={modalSource} />
    </div>
  )
}
