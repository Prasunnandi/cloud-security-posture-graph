import React, { useState } from 'react';
import { 
  ShieldAlert, 
  FileCode, 
  CheckCircle, 
  ExternalLink, 
  Copy, 
  Check, 
  Terminal, 
  AlertTriangle,
  Play,
  Flame,
  Search,
  Filter
} from 'lucide-react';

export default function CspmFindingsView({ findings, onRemediate }) {
  const [selectedFinding, setSelectedFinding] = useState(findings[0] || null);
  const [copied, setCopied] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [search, setSearch] = useState('');

  const filtered = findings.filter(f => {
    const matchesSev = filterSeverity === 'ALL' || f.severity === filterSeverity;
    const matchesSearch = f.attackVector.toLowerCase().includes(search.toLowerCase()) ||
                          f.resourceArn.toLowerCase().includes(search.toLowerCase()) ||
                          f.cisBenchmarkId.toLowerCase().includes(search.toLowerCase());
    return matchesSev && matchesSearch;
  });

  const handleCopyCode = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center space-x-2">
            <ShieldAlert className="w-5 h-5 text-rose-400" />
            <span>CSPM Security Posture Findings</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            CIS Cloud Benchmark & IaC Terraform scan results mapped to multi-cloud resources.
          </p>
        </div>

        <div className="flex items-center space-x-2 text-xs">
          <input
            type="text"
            placeholder="Search ARN, CIS, vector..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="bg-slate-900 border border-slate-800 text-slate-200 px-3 py-1.5 rounded-lg w-56 focus:outline-none focus:border-rose-500"
          />

          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-slate-900 border border-slate-800 text-slate-300 px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-rose-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical Only</option>
            <option value="HIGH">High Only</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Findings List */}
        <div className="lg:col-span-6 space-y-3 max-h-[620px] overflow-y-auto pr-1">
          {filtered.map((item) => {
            const isSelected = selectedFinding?.id === item.id;
            const isCritical = item.severity === 'CRITICAL';
            const isResolved = item.status === 'RESOLVED';

            return (
              <div
                key={item.id}
                onClick={() => setSelectedFinding(item)}
                className={`p-4 rounded-xl border cursor-pointer transition-all ${
                  isSelected
                    ? 'bg-slate-900 border-rose-500/80 shadow-md ring-1 ring-rose-500/40'
                    : 'bg-slate-900/60 border-slate-800 hover:bg-slate-900 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between text-xs mb-2">
                  <div className="flex items-center space-x-2">
                    <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                      isCritical ? 'bg-rose-500/20 text-rose-300' : 'bg-amber-500/20 text-amber-300'
                    }`}>
                      {item.severity}
                    </span>
                    <span className="font-mono text-slate-400 text-[11px]">{item.cisBenchmarkId}</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 font-medium">
                      {item.provider}
                    </span>
                  </div>

                  <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${
                    isResolved 
                      ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                      : 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                  }`}>
                    {item.status}
                  </span>
                </div>

                <h4 className="text-xs font-semibold text-white leading-snug">{item.attackVector}</h4>
                <p className="text-[11px] font-mono text-slate-400 truncate mt-1">{item.resourceArn}</p>

                <div className="mt-3 pt-2.5 border-t border-slate-800 flex items-center justify-between text-[10px]">
                  <span className="text-slate-400">Blast Radius: <strong className="text-rose-400 font-mono">{item.blastRadiusNodes} nodes</strong></span>
                  {item.toxicCombination && (
                    <span className="text-amber-400 font-semibold flex items-center space-x-1">
                      <Flame className="w-3 h-3 text-amber-400" />
                      <span>Toxic Chain</span>
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {/* Detailed Remediation Drawer */}
        <div className="lg:col-span-6 space-y-4">
          {selectedFinding ? (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-start justify-between border-b border-slate-800 pb-3">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-mono text-rose-400 bg-rose-950/60 border border-rose-800/60 px-2 py-0.5 rounded">
                      {selectedFinding.id}
                    </span>
                    <span className="text-xs text-slate-400 font-mono">{selectedFinding.cisBenchmarkId}</span>
                  </div>
                  <h3 className="text-base font-bold text-white mt-1.5">{selectedFinding.attackVector}</h3>
                </div>

                {selectedFinding.status !== 'RESOLVED' && (
                  <button
                    onClick={() => onRemediate(selectedFinding.id)}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-lg shadow-emerald-600/20 transition"
                  >
                    <CheckCircle className="w-3.5 h-3.5" />
                    <span>Apply Patch PR</span>
                  </button>
                )}
              </div>

              {/* Resource Info */}
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1 font-mono text-xs">
                <span className="text-slate-400 block text-[10px]">Target Resource Identifier (ARN):</span>
                <span className="text-cyan-400 break-all">{selectedFinding.resourceArn}</span>
              </div>

              {/* Terraform Remediation Code */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-300 font-semibold flex items-center space-x-1.5">
                    <FileCode className="w-3.5 h-3.5 text-rose-400" />
                    <span>Automated IaC Terraform Remediation Snippet</span>
                  </span>
                  <button
                    onClick={() => handleCopyCode(selectedFinding.remediationCode)}
                    className="flex items-center space-x-1 text-slate-400 hover:text-slate-200"
                  >
                    {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>

                <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs overflow-x-auto text-emerald-300">
                  <pre className="whitespace-pre-wrap">{selectedFinding.remediationCode}</pre>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 text-[11px] text-slate-400 leading-relaxed">
                Applying this patch will restrict the IAM action boundary or enforce public bucket blocks, cutting the reachable blast radius by <strong>{selectedFinding.blastRadiusNodes} downstream resources</strong>.
              </div>
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center text-slate-400 text-xs">
              Select a security finding to inspect remediation details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
