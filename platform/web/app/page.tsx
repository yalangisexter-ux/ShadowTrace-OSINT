"use client";

import { useState } from "react";
import {
  Activity, ArrowUpRight, Bell, Boxes, BriefcaseBusiness, ChevronDown,
  CircleHelp, Clock3, Command, Database, FileSearch, Fingerprint,
  Globe2, Network, Plus, Radar, Search, ShieldCheck, Sparkles,
  Workflow, Zap
} from "lucide-react";

const nav = [
  { label: "Overview", icon: Activity },
  { label: "Investigations", icon: BriefcaseBusiness },
  { label: "Entity explorer", icon: Network },
  { label: "Collectors", icon: Boxes },
  { label: "Workflows", icon: Workflow },
  { label: "Reports", icon: FileSearch }
];

const modules = [
  ["Domain intelligence", "DNS, certificates, subdomains", Globe2, "Ready"],
  ["IP intelligence", "ASN, reputation, infrastructure", Radar, "Planned"],
  ["Identity research", "Public usernames and profiles", Fingerprint, "Planned"],
  ["Evidence graph", "Entities, links and provenance", Network, "Planned"]
] as const;

export default function Home() {
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState("");
  const api = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  async function runCollection(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true); setError(""); setResult(null);
    try {
      const response = await fetch(`${api}/api/v1/collect/domain`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target })
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "Collection request failed");
      setResult(body);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to reach the API");
    } finally { setBusy(false); }
  }

  return (
    <main className="min-h-screen">
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-[248px] border-r border-line bg-[#0b1018]/95 px-5 py-6 lg:flex lg:flex-col">
        <div className="mb-10 flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-xl border border-indigo-300/20 bg-indigo-400/10 text-indigo-200"><Fingerprint size={22}/></div>
          <div><div className="text-sm font-semibold tracking-wide">SHADOWTRACE</div><div className="text-[10px] uppercase tracking-[.24em] text-slate-500">Intelligence platform</div></div>
        </div>
        <div className="mb-3 px-3 text-[10px] font-semibold uppercase tracking-[.2em] text-slate-600">Workspace</div>
        <div className="mb-7 flex items-center justify-between rounded-xl border border-line bg-white/[.03] px-3 py-3 text-sm"><span>Primary workspace</span><ChevronDown size={15} className="text-slate-500"/></div>
        <nav className="space-y-1">
          {nav.map((item, index) => <a key={item.label} href="#" className={`flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm ${index===0 ? "bg-indigo-400/10 text-indigo-200 ring-1 ring-indigo-300/15" : "text-slate-400 hover:bg-white/[.04] hover:text-white"}`}><item.icon size={17}/>{item.label}{index===1 && <span className="ml-auto rounded-md bg-white/5 px-1.5 py-0.5 text-[10px]">0</span>}</a>)}
        </nav>
        <div className="mb-3 mt-9 px-3 text-[10px] font-semibold uppercase tracking-[.2em] text-slate-600">System</div>
        <a className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-slate-400" href="#"><Database size={17}/>Data sources</a>
        <a className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-slate-400" href="#"><ShieldCheck size={17}/>Audit & access</a>
        <div className="mt-auto rounded-2xl border border-line bg-gradient-to-br from-indigo-400/10 to-transparent p-4">
          <div className="mb-2 flex items-center gap-2 text-xs font-semibold text-indigo-200"><Sparkles size={14}/> Analyst assistant</div>
          <p className="text-xs leading-5 text-slate-500">AI-assisted analysis will use sourced evidence and explain its confidence.</p>
          <div className="mt-3 flex items-center gap-2 text-[10px] text-slate-600"><span className="h-1.5 w-1.5 rounded-full bg-amber-400"/> Setup in progress</div>
        </div>
      </aside>

      <section className="lg:ml-[248px]">
        <header className="flex h-[72px] items-center justify-between border-b border-line px-5 sm:px-8">
          <div className="flex items-center gap-2 text-xs text-slate-500"><span>Workspace</span><span>/</span><span className="text-slate-200">Overview</span></div>
          <div className="flex items-center gap-3"><div className="hidden items-center gap-2 rounded-lg border border-line bg-white/[.03] px-3 py-2 text-xs text-slate-500 sm:flex"><Command size={13}/> Quick search <kbd className="ml-4 rounded border border-line px-1.5 py-0.5">⌘ K</kbd></div><button className="rounded-lg border border-line p-2 text-slate-400"><Bell size={16}/></button><div className="grid h-8 w-8 place-items-center rounded-full bg-gradient-to-br from-indigo-300 to-cyan-300 text-xs font-bold text-slate-950">ST</div></div>
        </header>

        <div className="mx-auto max-w-[1440px] px-5 py-8 sm:px-8">
          <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
            <div><div className="mb-2 flex items-center gap-2 text-xs text-mint"><span className="h-1.5 w-1.5 rounded-full bg-mint"/> INTELLIGENCE OPERATIONS</div><h1 className="text-3xl font-semibold tracking-tight sm:text-[34px]">Good afternoon, Analyst.</h1><p className="mt-2 text-sm text-slate-500">Your evidence-led investigation workspace.</p></div>
            <button className="flex items-center gap-2 rounded-xl bg-indigo-300 px-4 py-2.5 text-sm font-semibold text-slate-950 shadow-glow"><Plus size={16}/> New investigation</button>
          </div>

          <div className="mb-7 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {[
              ["Active investigations","0","No active cases"],
              ["Evidence collected","0","Awaiting first collection"],
              ["Collectors available","1","Passive domain collector"],
              ["Background jobs","0","Queue not enabled yet"]
            ].map(([label,value,note]) => <div key={label} className="rounded-2xl border border-line bg-[#111722]/80 p-5"><div className="flex items-center justify-between text-xs text-slate-500"><span>{label}</span><Activity size={16}/></div><div className="mt-4 text-3xl font-semibold tracking-tight">{value}</div><div className="mt-1 text-xs text-slate-600">{note}</div></div>)}
          </div>

          <div className="mb-7 grid gap-5 xl:grid-cols-[1.5fr_1fr]">
            <div className="rounded-2xl border border-line bg-[#111722]/85 p-5 sm:p-6">
              <div className="mb-2 flex items-center gap-2 text-sm font-semibold"><Search size={17} className="text-indigo-300"/> Start passive domain collection</div>
              <p className="mb-5 text-xs leading-5 text-slate-500">Collect DNS records and public Certificate Transparency references for a domain you are authorized to investigate.</p>
              <form onSubmit={runCollection} className="flex flex-col gap-2 sm:flex-row">
                <input value={target} onChange={e=>setTarget(e.target.value)} required placeholder="example.com" className="min-w-0 flex-1 rounded-xl border border-line bg-[#090e16] px-4 py-3 text-sm outline-none placeholder:text-slate-700 focus:border-indigo-300/60"/>
                <button disabled={busy} className="flex items-center justify-center gap-2 rounded-xl bg-indigo-300 px-5 py-3 text-sm font-semibold text-slate-950 disabled:opacity-50">{busy ? "Collecting…" : "Run collection"}<ArrowUpRight size={16}/></button>
              </form>
              {error && <p className="mt-3 text-xs text-rose-300">{error}</p>}
              {result && <div className="mt-5 rounded-xl border border-mint/20 bg-mint/[.05] p-4"><div className="mb-2 flex items-center justify-between text-xs"><span className="font-semibold text-mint">Collection complete</span><span className="text-slate-500">{result.observations.length} observations</span></div><div className="max-h-56 space-y-2 overflow-auto">{result.observations.map((item:any,i:number)=><div key={i} className="flex flex-wrap justify-between gap-2 border-t border-white/5 pt-2 text-xs"><span className="text-slate-300">{item.relation || item.entity_type}</span><span className="break-all text-slate-500">{item.value}</span></div>)}</div></div>}
            </div>
            <div className="rounded-2xl border border-line bg-[#111722]/85 p-5 sm:p-6">
              <div className="mb-4 flex items-center justify-between"><div className="text-sm font-semibold">Platform status</div><span className="rounded-full border border-amber-300/20 bg-amber-300/10 px-2 py-1 text-[10px] text-amber-200">Foundation phase</span></div>
              <div className="space-y-4">
                {[["API service","Ready","bg-mint"],["Passive domain collector","Ready","bg-mint"],["PostgreSQL persistence","Configured, not wired","bg-amber-300"],["Redis task queue","Configured, not wired","bg-amber-300"],["AI orchestration","Planned","bg-slate-600"]].map(([name,status,dot])=><div key={name} className="flex items-center justify-between text-xs"><span className="text-slate-400">{name}</span><span className="flex items-center gap-2 text-slate-500"><i className={`h-1.5 w-1.5 rounded-full ${dot}`}/>{status}</span></div>)}
              </div>
              <div className="mt-5 border-t border-line pt-4 text-[11px] leading-5 text-slate-600"><ShieldCheck size={14} className="mr-1 inline text-mint"/> Evidence provenance is retained. A match is a lead, never identity proof.</div>
            </div>
          </div>

          <div className="mb-3 flex items-center justify-between"><div><h2 className="text-lg font-semibold">Intelligence modules</h2><p className="mt-1 text-xs text-slate-500">Extensible collectors, independently enabled.</p></div><a href="#" className="text-xs text-indigo-200">View module catalog <ArrowUpRight size={13} className="inline"/></a></div>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {modules.map(([name,desc,Icon,status])=><div key={name} className="rounded-2xl border border-line bg-[#111722]/65 p-4 transition hover:border-indigo-300/30"><div className="mb-4 flex items-center justify-between"><div className="grid h-9 w-9 place-items-center rounded-xl bg-indigo-300/10 text-indigo-200"><Icon size={18}/></div><span className={`rounded-full px-2 py-1 text-[10px] ${status==="Ready"?"bg-mint/10 text-mint":"bg-white/5 text-slate-500"}`}>{status}</span></div><div className="text-sm font-semibold">{name}</div><div className="mt-1 text-xs text-slate-500">{desc}</div></div>)}
          </div>
          <footer className="mt-10 flex flex-wrap items-center justify-between gap-2 border-t border-line py-5 text-[10px] text-slate-600"><span>SHADOWTRACE INTELLIGENCE · DEVELOPMENT BUILD</span><span className="flex items-center gap-2"><Zap size={12}/> Built for transparent, lawful research <CircleHelp size={12}/></span></footer>
        </div>
      </section>
    </main>
  );
}
