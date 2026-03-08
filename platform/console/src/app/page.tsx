// Copyright 2024 Omni Cyber Solutions LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Link from "next/link";

// ─── Nav ─────────────────────────────────────────────────────────────────────

function Nav() {
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 border-b border-white/5 bg-[#020817]/80 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
        {/* Logo */}
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-400 flex items-center justify-center flex-shrink-0">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <path d="M7 1L12 4V10L7 13L2 10V4L7 1Z" stroke="white" strokeWidth="1.5" strokeLinejoin="round"/>
              <circle cx="7" cy="7" r="2" fill="white"/>
            </svg>
          </div>
          <span className="text-white font-bold text-lg tracking-tight">OmniProtect</span>
        </div>

        {/* Links */}
        <div className="hidden md:flex items-center gap-8 text-sm text-slate-400">
          <a href="#features" className="hover:text-white transition-colors">Features</a>
          <a href="#how-it-works" className="hover:text-white transition-colors">How it works</a>
          <a href="#technology" className="hover:text-white transition-colors">Technology</a>
          <a
            href="https://github.com/OCSGroup101/Business_AIProtector"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-white transition-colors flex items-center gap-1.5"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
              <path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/>
            </svg>
            GitHub
          </a>
        </div>

        {/* CTAs */}
        <div className="flex items-center gap-3">
          <Link
            href="/login?tab=tenant"
            className="hidden sm:inline-flex px-4 py-2 text-sm text-slate-300 hover:text-white border border-slate-700 hover:border-slate-500 rounded-lg transition-all"
          >
            Sign in
          </Link>
          <Link
            href="/login?tab=msp"
            className="inline-flex items-center gap-1.5 px-4 py-2 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors shadow-lg shadow-blue-600/20"
          >
            MSP Portal
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 16 16" stroke="currentColor" strokeWidth="2">
              <path d="M3 8h10M8.5 3.5L13 8l-4.5 4.5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </Link>
        </div>
      </div>
    </nav>
  );
}

// ─── Hero ─────────────────────────────────────────────────────────────────────

function Hero() {
  return (
    <section className="relative min-h-screen bg-hero-glow bg-grid flex flex-col items-center justify-center pt-16 overflow-hidden">
      {/* Glow blobs */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[600px] bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute top-1/3 right-1/4 w-[300px] h-[300px] bg-cyan-500/8 rounded-full blur-3xl pointer-events-none" />

      <div className="relative max-w-7xl mx-auto px-6 py-20 flex flex-col items-center text-center">
        {/* Eyebrow badge */}
        <div className="animate-fade-in-up inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 text-blue-300 text-xs font-medium mb-8">
          <span className="w-1.5 h-1.5 rounded-full bg-blue-400 pulse-dot" />
          v2.0 — AI-Enhanced Detection is live
        </div>

        {/* Headline */}
        <h1 className="animate-fade-in-up max-w-4xl text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight leading-tight text-white mb-6">
          Endpoint Security{" "}
          <span className="text-gradient">Built for MSPs</span>
          <br />
          <span className="text-gradient-white">Not Megacorps</span>
        </h1>

        {/* Sub */}
        <p className="animate-fade-in-up-delay max-w-2xl text-lg text-slate-400 leading-relaxed mb-10">
          OmniProtect delivers world-class threat detection and response at a fraction of the cost.
          Full data sovereignty. Deploy anywhere in under 30 minutes.
        </p>

        {/* CTA buttons */}
        <div className="animate-fade-in-up-delay-2 flex flex-col sm:flex-row items-center gap-4 mb-16">
          <Link
            href="/login?tab=msp"
            className="flex items-center gap-2 px-7 py-3.5 text-base font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-xl transition-all shadow-xl shadow-blue-600/25 hover:shadow-blue-500/30 hover:-translate-y-0.5"
          >
            Start Free — MSP Portal
            <svg className="w-4 h-4" fill="none" viewBox="0 0 16 16" stroke="currentColor" strokeWidth="2">
              <path d="M3 8h10M8.5 3.5L13 8l-4.5 4.5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </Link>
          <Link
            href="/login?tab=tenant"
            className="flex items-center gap-2 px-7 py-3.5 text-base font-semibold text-slate-300 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-white/20 rounded-xl transition-all"
          >
            Tenant Console
          </Link>
          <a
            href="https://github.com/OCSGroup101/Business_AIProtector"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 text-base text-slate-500 hover:text-slate-300 transition-colors px-3"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
              <path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/>
            </svg>
            View on GitHub
          </a>
        </div>

        {/* Dashboard mockup */}
        <div className="w-full max-w-5xl">
          <DashboardMockup />
        </div>
      </div>
    </section>
  );
}

function DashboardMockup() {
  return (
    <div className="rounded-2xl border border-white/10 bg-slate-900/80 shadow-2xl shadow-black/60 backdrop-blur overflow-hidden">
      {/* Window chrome */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-white/5 bg-slate-950/60">
        <div className="w-3 h-3 rounded-full bg-red-500/70" />
        <div className="w-3 h-3 rounded-full bg-yellow-500/70" />
        <div className="w-3 h-3 rounded-full bg-green-500/70" />
        <span className="ml-3 text-xs text-slate-600 font-mono">OmniProtect MSP — dashboard</span>
      </div>

      {/* Content */}
      <div className="flex divide-x divide-white/5">
        {/* Sidebar */}
        <div className="w-48 flex-shrink-0 bg-slate-950/40 p-3 space-y-0.5">
          {[
            { label: "Dashboard", active: true },
            { label: "Clients", active: false },
            { label: "Alerts", active: false },
            { label: "Enrollment", active: false },
            { label: "Audit Log", active: false },
          ].map((item) => (
            <div
              key={item.label}
              className={`px-3 py-1.5 rounded-lg text-xs transition-colors ${
                item.active
                  ? "bg-blue-600/20 text-blue-400 font-medium"
                  : "text-slate-600"
              }`}
            >
              {item.label}
            </div>
          ))}
        </div>

        {/* Main panel */}
        <div className="flex-1 p-5 space-y-5">
          {/* Stat row */}
          <div className="grid grid-cols-4 gap-3">
            {[
              { label: "Clients", value: "24", color: "text-blue-400" },
              { label: "Agents", value: "1,847", color: "text-green-400" },
              { label: "Open Incidents", value: "3", color: "text-yellow-400" },
              { label: "Critical", value: "1", color: "text-red-400" },
            ].map((s) => (
              <div key={s.label} className="bg-slate-800/60 rounded-lg p-3 border border-white/5">
                <p className={`text-xl font-bold ${s.color}`}>{s.value}</p>
                <p className="text-xs text-slate-600 mt-0.5">{s.label}</p>
              </div>
            ))}
          </div>

          {/* Table */}
          <div className="bg-slate-800/40 rounded-lg border border-white/5 overflow-hidden">
            <div className="px-3 py-2 border-b border-white/5 flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Recent Alerts</span>
              <span className="text-xs text-slate-600">Last 24h</span>
            </div>
            <div className="divide-y divide-white/3">
              {[
                { sev: "CRITICAL", client: "Acme Corp", rule: "LSASS Memory Dump", host: "WIN-DC01", time: "2m ago", sevColor: "bg-red-500 text-white" },
                { sev: "HIGH", client: "TechStart Inc", rule: "Suspicious PowerShell", host: "DESKTOP-44X", time: "18m ago", sevColor: "bg-orange-500 text-white" },
                { sev: "MEDIUM", client: "BuildCo LLC", rule: "Lateral Movement IOC", host: "SRV-FILE01", time: "1h ago", sevColor: "bg-yellow-500 text-black" },
              ].map((row) => (
                <div key={row.host} className="px-3 py-2 flex items-center gap-3 text-xs hover:bg-white/3">
                  <span className={`px-1.5 py-0.5 rounded text-xs font-bold flex-shrink-0 ${row.sevColor}`}>{row.sev}</span>
                  <span className="text-blue-400 w-24 flex-shrink-0 truncate">{row.client}</span>
                  <span className="text-slate-300 flex-1 truncate">{row.rule}</span>
                  <span className="text-slate-600 font-mono flex-shrink-0">{row.host}</span>
                  <span className="text-slate-600 flex-shrink-0">{row.time}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Social proof strip ───────────────────────────────────────────────────────

function StatsStrip() {
  const stats = [
    { value: "48", label: "Detection Rules" },
    { value: "12", label: "MITRE Tactics Covered" },
    { value: "4", label: "Supported Platforms" },
    { value: "<1s", label: "Alert Latency" },
    { value: "100%", label: "Open Source" },
  ];

  return (
    <section className="border-y border-slate-800 bg-slate-900/50">
      <div className="max-w-7xl mx-auto px-6 py-10 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-8">
        {stats.map(({ value, label }) => (
          <div key={label} className="text-center">
            <p className="text-3xl font-bold text-white mb-1">{value}</p>
            <p className="text-sm text-slate-500">{label}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

// ─── Features ─────────────────────────────────────────────────────────────────

const FEATURES = [
  {
    title: "AI-Powered Correlation",
    description:
      "LangGraph multi-agent correlation engine connects disparate events across endpoints to surface attack campaigns that rule-based systems miss.",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.456 2.456L21.75 6l-1.035.259a3.375 3.375 0 00-2.456 2.456z" />
      </svg>
    ),
    color: "from-blue-500 to-cyan-400",
    bg: "bg-blue-500/10",
    border: "border-blue-500/20",
  },
  {
    title: "Lightweight Rust Agent",
    description:
      "≤4% CPU and ≤80 MB RAM steady-state. eBPF collectors on Linux, ESF on macOS, ETW on Windows — deep visibility without the performance tax.",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
        <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 3v1.5M4.5 8.25H3m18 0h-1.5M4.5 12H3m18 0h-1.5m-15 3.75H3m18 0h-1.5M8.25 19.5V21M12 3v1.5m0 15V21m3.75-18v1.5m0 15V21m-9-1.5h10.5a2.25 2.25 0 002.25-2.25V6.75a2.25 2.25 0 00-2.25-2.25H6.75A2.25 2.25 0 004.5 6.75v10.5a2.25 2.25 0 002.25 2.25zm.75-12h9v9h-9v-9z" />
      </svg>
    ),
    color: "from-violet-500 to-purple-400",
    bg: "bg-violet-500/10",
    border: "border-violet-500/20",
  },
  {
    title: "Multi-Tenant MSP Architecture",
    description:
      "Schema-per-tenant PostgreSQL isolation. Provision clients in seconds, drill into any tenant console from the MSP portal, generate enrollment tokens on demand.",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
        <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 21h19.5m-18-18v18m10.5-18v18m6-13.5V21M6.75 6.75h.75m-.75 3h.75m-.75 3h.75m3-6h.75m-.75 3h.75m-.75 3h.75M6.75 21v-3.375c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21M3 3h12m-.75 4.5H21m-3.75 3.75h.008v.008h-.008v-.008zm0 3h.008v.008h-.008v-.008zm0 3h.008v.008h-.008v-.008z" />
      </svg>
    ),
    color: "from-emerald-500 to-green-400",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/20",
  },
  {
    title: "Live Threat Intelligence",
    description:
      "Automated IOC ingestion from CISA KEV, MalwareBazaar, AlienVault OTX, and MISP. LMDB-backed local store delivers sub-millisecond IOC lookups.",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.249-8.25-3.286zm0 13.036h.008v.008H12v-.008z" />
      </svg>
    ),
    color: "from-orange-500 to-amber-400",
    bg: "bg-orange-500/10",
    border: "border-orange-500/20",
  },
  {
    title: "MITRE ATT&CK Coverage",
    description:
      "Interactive heatmap shows exactly which ATT&CK techniques are covered per tenant. Identify detection gaps and prioritize rule development with data.",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
        <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 3v11.25A2.25 2.25 0 006 16.5h2.25M3.75 3h-1.5m1.5 0h16.5m0 0h1.5m-1.5 0v11.25A2.25 2.25 0 0118 16.5h-2.25m-7.5 0h7.5m-7.5 0l-1 3m8.5-3l1 3m0 0l.5 1.5m-.5-1.5h-9.5m0 0l-.5 1.5M9 11.25v1.5M12 9v3.75m3-6v6" />
      </svg>
    ),
    color: "from-red-500 to-rose-400",
    bg: "bg-red-500/10",
    border: "border-red-500/20",
  },
  {
    title: "Zero Vendor Lock-in",
    description:
      "Apache 2.0 licensed — use it, fork it, sell it. Full Helm chart for RKE2/K3s, a typed Python integration SDK, and sovereign CI via Forgejo Actions.",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
        <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 10.5V6.75a4.5 4.5 0 119 0v3.75M3.75 21.75h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H3.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
      </svg>
    ),
    color: "from-slate-400 to-slate-300",
    bg: "bg-slate-500/10",
    border: "border-slate-500/20",
  },
];

function Features() {
  return (
    <section id="features" className="bg-[#020817] py-24">
      <div className="max-w-7xl mx-auto px-6">
        {/* Header */}
        <div className="text-center max-w-2xl mx-auto mb-16">
          <p className="text-sm font-semibold text-blue-400 uppercase tracking-widest mb-3">
            Platform Capabilities
          </p>
          <h2 className="text-4xl font-bold text-white mb-4">
            Everything your security team needs
          </h2>
          <p className="text-slate-400 text-lg">
            Purpose-built for Managed Security Service Providers delivering EDR to multiple clients from a single pane of glass.
          </p>
        </div>

        {/* Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {FEATURES.map(({ title, description, icon, color, bg, border }) => (
            <div
              key={title}
              className={`group relative rounded-2xl border ${border} ${bg} p-6 card-glow transition-all duration-300`}
            >
              <div className={`inline-flex p-2.5 rounded-xl bg-gradient-to-br ${color} mb-4`}>
                <span className="text-white">{icon}</span>
              </div>
              <h3 className="text-base font-semibold text-white mb-2">{title}</h3>
              <p className="text-sm text-slate-400 leading-relaxed">{description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ─── How it works ─────────────────────────────────────────────────────────────

function HowItWorks() {
  const steps = [
    {
      number: "01",
      title: "Deploy the stack",
      description:
        "Run `make dev-up` or apply the Helm chart to your K3s/RKE2 cluster. The full platform — API, Kafka, Keycloak, PostgreSQL, Redis — is up in under 5 minutes.",
      code: "helm install omniprotect helm/omniprotect/ \\\n  --set keycloak.enabled=true \\\n  --set kafka.enabled=true",
    },
    {
      number: "02",
      title: "Provision clients & enroll agents",
      description:
        "Create tenants in the MSP portal, generate enrollment tokens, and deploy the Rust agent to endpoints. One command installs and enrolls automatically.",
      code: "curl -fsSL https://get.omniprotect.io/agent \\\n  | ENROLLMENT_TOKEN=\"tok_xxx\" bash",
    },
    {
      number: "03",
      title: "Detect, correlate & respond",
      description:
        "Live threat intelligence populates the IOC store. Behavioral rules fire. The AI correlation engine links events into campaigns. Respond with one-click isolation.",
      code: "POST /api/v1/agents/{id}/isolate\nPOST /api/v1/correlation/analyze",
    },
  ];

  return (
    <section id="how-it-works" className="bg-slate-950 py-24">
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center max-w-2xl mx-auto mb-16">
          <p className="text-sm font-semibold text-blue-400 uppercase tracking-widest mb-3">
            Getting Started
          </p>
          <h2 className="text-4xl font-bold text-white mb-4">
            From zero to protected in minutes
          </h2>
          <p className="text-slate-400 text-lg">
            No 6-week onboarding, no professional services engagement. Self-hosted, self-managed, fully yours.
          </p>
        </div>

        <div className="space-y-6">
          {steps.map((step, i) => (
            <div
              key={step.number}
              className="flex flex-col lg:flex-row gap-8 items-start p-8 rounded-2xl border border-slate-800 bg-slate-900/40 hover:border-slate-700 transition-colors"
            >
              {/* Left */}
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-4">
                  <span className="text-4xl font-black text-slate-800">{step.number}</span>
                  <div className="h-px flex-1 bg-slate-800" />
                </div>
                <h3 className="text-xl font-bold text-white mb-3">{step.title}</h3>
                <p className="text-slate-400 leading-relaxed">{step.description}</p>
              </div>

              {/* Code block */}
              <div className="lg:w-96 w-full flex-shrink-0">
                <div className="rounded-xl bg-slate-950 border border-slate-800 overflow-hidden">
                  <div className="flex items-center gap-2 px-4 py-2.5 border-b border-slate-800">
                    <div className="w-2.5 h-2.5 rounded-full bg-red-500/50" />
                    <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/50" />
                    <div className="w-2.5 h-2.5 rounded-full bg-green-500/50" />
                  </div>
                  <pre className="p-4 text-xs font-mono text-green-400 leading-relaxed overflow-x-auto">
                    <code>{step.code}</code>
                  </pre>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ─── Technology ───────────────────────────────────────────────────────────────

function Technology() {
  const stack = [
    { name: "Rust 1.77", desc: "Agent runtime" },
    { name: "FastAPI", desc: "Platform API" },
    { name: "Next.js 14", desc: "Console" },
    { name: "PostgreSQL 16", desc: "Schema-per-tenant" },
    { name: "Kafka 3.8", desc: "Event streaming" },
    { name: "Keycloak 26", desc: "Identity & SSO" },
    { name: "Redis 7", desc: "Cache layer" },
    { name: "Claude Opus 4.6", desc: "AI correlation" },
    { name: "Helm / K3s", desc: "Deployment" },
  ];

  return (
    <section id="technology" className="bg-[#020817] py-24 border-t border-slate-900">
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center max-w-xl mx-auto mb-12">
          <p className="text-sm font-semibold text-blue-400 uppercase tracking-widest mb-3">
            Technology
          </p>
          <h2 className="text-3xl font-bold text-white mb-3">
            No half-measures. Best-in-class stack.
          </h2>
          <p className="text-slate-400">
            Every component chosen for performance, security, and long-term maintainability.
          </p>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-9 gap-px bg-slate-800 rounded-2xl overflow-hidden">
          {stack.map(({ name, desc }) => (
            <div
              key={name}
              className="bg-slate-950 hover:bg-slate-900 transition-colors p-5 flex flex-col items-center text-center"
            >
              <p className="text-sm font-semibold text-white mb-1">{name}</p>
              <p className="text-xs text-slate-600">{desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ─── Comparison ───────────────────────────────────────────────────────────────

function Comparison() {
  const rows = [
    { feature: "Deployment model", omniprotect: "Self-hosted or cloud", others: "Cloud-only / SaaS" },
    { feature: "Data sovereignty", omniprotect: "Full — your infrastructure", others: "Vendor-held telemetry" },
    { feature: "Per-seat licensing", omniprotect: "None — open source", others: "$15–$60 per endpoint/mo" },
    { feature: "Multi-tenant MSP portal", omniprotect: "Built-in", others: "Limited / separate product" },
    { feature: "Agent resource usage", omniprotect: "≤4% CPU, ≤80 MB RAM", others: "5–15% CPU typical" },
    { feature: "AI correlation", omniprotect: "Claude Opus + LangGraph", others: "Proprietary, opaque" },
    { feature: "Source code access", omniprotect: "Apache 2.0 — fully open", others: "Closed source" },
  ];

  return (
    <section className="bg-slate-950 py-24 border-t border-slate-900">
      <div className="max-w-5xl mx-auto px-6">
        <div className="text-center mb-12">
          <p className="text-sm font-semibold text-blue-400 uppercase tracking-widest mb-3">
            Why OmniProtect
          </p>
          <h2 className="text-3xl font-bold text-white mb-3">
            The enterprise alternative that you actually own
          </h2>
          <p className="text-slate-400">
            Compare against leading enterprise EDR vendors on the market.
          </p>
        </div>

        <div className="rounded-2xl border border-slate-800 overflow-hidden">
          {/* Header row */}
          <div className="grid grid-cols-3 bg-slate-900 px-6 py-4 border-b border-slate-800">
            <div className="text-sm text-slate-500 font-medium">Feature</div>
            <div className="text-sm font-bold text-blue-400 text-center flex items-center justify-center gap-2">
              <div className="w-4 h-4 rounded bg-gradient-to-br from-blue-500 to-cyan-400 flex items-center justify-center">
                <svg width="8" height="8" viewBox="0 0 14 14" fill="none">
                  <path d="M7 1L12 4V10L7 13L2 10V4L7 1Z" stroke="white" strokeWidth="1.5" strokeLinejoin="round"/>
                  <circle cx="7" cy="7" r="2" fill="white"/>
                </svg>
              </div>
              OmniProtect
            </div>
            <div className="text-sm text-slate-500 text-center">Enterprise EDR vendors</div>
          </div>

          {rows.map((row, i) => (
            <div
              key={row.feature}
              className={`grid grid-cols-3 px-6 py-4 border-b border-slate-800/60 last:border-0 ${
                i % 2 === 0 ? "bg-slate-950" : "bg-slate-900/20"
              }`}
            >
              <div className="text-sm text-slate-400">{row.feature}</div>
              <div className="text-sm text-white font-medium text-center flex items-center justify-center gap-1.5">
                <svg className="w-4 h-4 text-green-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                </svg>
                {row.omniprotect}
              </div>
              <div className="text-sm text-slate-500 text-center">{row.others}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ─── CTA ──────────────────────────────────────────────────────────────────────

function FinalCTA() {
  return (
    <section className="bg-[#020817] py-24 border-t border-slate-900">
      <div className="max-w-4xl mx-auto px-6 text-center">
        <div className="relative rounded-3xl border border-blue-500/20 bg-gradient-to-b from-blue-950/40 to-slate-950 p-12 overflow-hidden">
          {/* Glow */}
          <div className="absolute inset-0 bg-gradient-to-br from-blue-600/5 to-transparent pointer-events-none" />
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-64 h-px bg-gradient-to-r from-transparent via-blue-500/50 to-transparent" />

          <div className="relative">
            <p className="text-sm font-semibold text-blue-400 uppercase tracking-widest mb-4">
              Get Started Today
            </p>
            <h2 className="text-4xl font-bold text-white mb-4">
              Ready to secure your clients&apos; endpoints?
            </h2>
            <p className="text-slate-400 text-lg mb-10 max-w-xl mx-auto">
              Deploy in under 30 minutes. No sales call, no contract negotiation, no per-seat fees.
              Full source code included.
            </p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link
                href="/login?tab=msp"
                className="flex items-center gap-2 px-8 py-4 text-base font-bold text-white bg-blue-600 hover:bg-blue-500 rounded-xl transition-all shadow-xl shadow-blue-600/30 hover:-translate-y-0.5 hover:shadow-blue-500/40"
              >
                Launch MSP Portal
                <svg className="w-4 h-4" fill="none" viewBox="0 0 16 16" stroke="currentColor" strokeWidth="2">
                  <path d="M3 8h10M8.5 3.5L13 8l-4.5 4.5" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </Link>
              <Link
                href="/login?tab=tenant"
                className="flex items-center gap-2 px-8 py-4 text-base font-semibold text-slate-300 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-white/20 rounded-xl transition-all"
              >
                Tenant Sign In
              </Link>
            </div>

            <p className="mt-6 text-xs text-slate-600">
              Apache 2.0 Licensed · Full source at github.com/OCSGroup101/Business_AIProtector
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

// ─── Footer ───────────────────────────────────────────────────────────────────

function Footer() {
  return (
    <footer className="bg-[#020817] border-t border-slate-900">
      <div className="max-w-7xl mx-auto px-6 py-12">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-8">
          {/* Brand */}
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-400 flex items-center justify-center">
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                <path d="M7 1L12 4V10L7 13L2 10V4L7 1Z" stroke="white" strokeWidth="1.5" strokeLinejoin="round"/>
                <circle cx="7" cy="7" r="2" fill="white"/>
              </svg>
            </div>
            <div>
              <span className="text-white font-bold">OmniProtect</span>
              <p className="text-xs text-slate-600">by Omni Cyber Solutions LLC</p>
            </div>
          </div>

          {/* Links */}
          <div className="flex flex-wrap gap-6 text-sm text-slate-500">
            <a href="#features" className="hover:text-slate-300 transition-colors">Features</a>
            <a href="#how-it-works" className="hover:text-slate-300 transition-colors">Docs</a>
            <Link href="/login" className="hover:text-slate-300 transition-colors">Sign In</Link>
            <a
              href="https://github.com/OCSGroup101/Business_AIProtector"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-slate-300 transition-colors"
            >
              GitHub
            </a>
          </div>

          <p className="text-xs text-slate-700">
            &copy; {new Date().getFullYear()} Omni Cyber Solutions LLC · Apache 2.0 · v2.0.0
          </p>
        </div>
      </div>
    </footer>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-[#020817] text-slate-100">
      <Nav />
      <Hero />
      <StatsStrip />
      <Features />
      <HowItWorks />
      <Technology />
      <Comparison />
      <FinalCTA />
      <Footer />
    </div>
  );
}
