import React, { useState } from 'react';
import { 
  Network, 
  ShieldAlert, 
  AlertTriangle, 
  ArrowRight, 
  Radio, 
  Layers, 
  Terminal, 
  Crosshair, 
  Flame, 
  CheckCircle2,
  Lock,
  Server,
  Cloud
} from 'lucide-react';

export default function AttackPathGraphView({ nodes, edges }) {
  const [selectedNode, setSelectedNode] = useState(nodes[1] || nodes[0]); // Bastion EC2 by default
  const [filterToxicOnly, setFilterToxicOnly] = useState(false);

  // Compute blast radius: find all nodes reachable from selectedNode
  const getDownstreamAssets = (nodeId) => {
    const visited = new Set();
    const queue = [nodeId];
    while (queue.length > 0) {
      const curr = queue.shift();
      if (!visited.has(curr)) {
        visited.add(curr);
        const outgoing = edges.filter(e => e.source === curr);
        for (const edge of outgoing) {
          if (!visited.has(edge.target)) {
            queue.push(edge.target);
          }
        }
      }
    }
    return Array.from(visited);
  };

  const downstreamIds = selectedNode ? getDownstreamAssets(selectedNode.id) : [];

  return (
    <div className="space-y-6">
      {/* Top Banner KPI Summary */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Critical Attack Paths</span>
            <Flame className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-rose-400 font-mono">3 Active</span>
            <span className="text-xs text-rose-500/80 font-medium">Internet-to-Admin</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400">
            Lateral escalation paths detected in IaC
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Toxic Combinations</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-amber-400 font-mono">4 Vectors</span>
            <span className="text-xs text-amber-500/80 font-medium">Multi-Control Fail</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400">
            Public ingress + Wildcard IAM permissions
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Max Blast Radius</span>
            <Crosshair className="w-4 h-4 text-purple-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-purple-400 font-mono">42 Cloud Assets</span>
            <span className="text-xs text-slate-400">from DevOpsAdmin</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400">
            Reachable data stores & KMS keys
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>IaC CIS Compliance</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-emerald-400 font-mono">68.4%</span>
            <span className="text-xs text-emerald-500/80 font-medium">+4.2% this week</span>
          </div>
          <div className="mt-2 text-[11px] text-slate-400">
            CIS AWS Foundations Benchmark v2.0
          </div>
        </div>
      </div>

      {/* Main Interactive Attack Graph Canvas & Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Visual Attack Graph Representation */}
        <div className="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div>
              <h2 className="text-sm font-bold text-white flex items-center space-x-2">
                <Network className="w-4 h-4 text-rose-400" />
                <span>IAM & Cloud Ingress Attack Topology</span>
              </h2>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Click any asset node to compute its live blast radius and downstream escalation edges.
              </p>
            </div>

            <div className="flex items-center space-x-2">
              <button
                onClick={() => setFilterToxicOnly(!filterToxicOnly)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition ${
                  filterToxicOnly 
                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/50' 
                    : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
                }`}
              >
                {filterToxicOnly ? 'Showing Toxic Paths Only' : 'Show All Edges'}
              </button>
            </div>
          </div>

          {/* Graph Nodes Grid Layout */}
          <div className="bg-slate-950/80 rounded-xl p-6 border border-slate-800/80 relative min-h-[460px] flex flex-col justify-between">
            {/* Tier 1: Ingress & Perimeter */}
            <div>
              <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-2">
                Zone 0: Ingress & DMZ
              </div>
              <div className="grid grid-cols-2 gap-3">
                {nodes.filter(n => n.type === 'EXTERNAL' || n.id === 'bastion-ec2').map((node) => {
                  const isSelected = selectedNode?.id === node.id;
                  const isImpacted = downstreamIds.includes(node.id);

                  return (
                    <div
                      key={node.id}
                      onClick={() => setSelectedNode(node)}
                      className={`p-3 rounded-lg border cursor-pointer transition-all ${
                        isSelected
                          ? 'bg-rose-950/60 border-rose-500 shadow-lg shadow-rose-500/20 ring-1 ring-rose-500'
                          : isImpacted
                          ? 'bg-amber-950/40 border-amber-600/70'
                          : 'bg-slate-900/90 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between text-xs font-semibold">
                        <span className={node.type === 'EXTERNAL' ? 'text-rose-400' : 'text-slate-200'}>
                          {node.label}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300">
                          Risk: {node.riskScore}
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-400 mt-1 flex items-center space-x-2">
                        <span>{node.type}</span>
                        <span>•</span>
                        <span>{node.zone}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Attack Traversal Indicator */}
            <div className="py-2 flex items-center justify-center space-x-3 text-slate-600 text-xs font-mono">
              <div className="h-px bg-slate-800 flex-1"></div>
              <span className="text-[10px] text-rose-400 font-semibold px-2 py-0.5 rounded bg-rose-950/50 border border-rose-800/50 flex items-center space-x-1">
                <span>⚡ Lateral Movement: SSH Ingress ➔ Lambda Role Injection</span>
              </span>
              <div className="h-px bg-slate-800 flex-1"></div>
            </div>

            {/* Tier 2: Compute & IAM Control Plane */}
            <div>
              <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-2">
                Zone 1: Workload & IAM Escalation
              </div>
              <div className="grid grid-cols-3 gap-3">
                {nodes.filter(n => n.type === 'SERVERLESS' || n.type === 'IAM_ROLE' || n.type === 'IAM_POLICY').map((node) => {
                  const isSelected = selectedNode?.id === node.id;
                  const isImpacted = downstreamIds.includes(node.id);

                  return (
                    <div
                      key={node.id}
                      onClick={() => setSelectedNode(node)}
                      className={`p-3 rounded-lg border cursor-pointer transition-all ${
                        isSelected
                          ? 'bg-rose-950/60 border-rose-500 shadow-lg shadow-rose-500/20 ring-1 ring-rose-500'
                          : isImpacted
                          ? 'bg-amber-950/40 border-amber-600/70'
                          : 'bg-slate-900/90 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between text-xs font-semibold">
                        <span className="text-slate-200 truncate">{node.label}</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300">
                          {node.riskScore}
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-400 mt-1 flex items-center space-x-1.5">
                        <span className="text-amber-400">{node.type}</span>
                        <span>•</span>
                        <span className="truncate">{node.zone}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Attack Traversal Indicator */}
            <div className="py-2 flex items-center justify-center space-x-3 text-slate-600 text-xs font-mono">
              <div className="h-px bg-slate-800 flex-1"></div>
              <span className="text-[10px] text-purple-400 font-semibold px-2 py-0.5 rounded bg-purple-950/50 border border-purple-800/50 flex items-center space-x-1">
                <span>🔥 Privilege Escalation: iam:PassRole + lambda:CreateFunction ➔ Data Exfiltration</span>
              </span>
              <div className="h-px bg-slate-800 flex-1"></div>
            </div>

            {/* Tier 3: Critical Data Assets & Secrets */}
            <div>
              <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-2">
                Zone 2: Crown Jewels & Cryptographic Core
              </div>
              <div className="grid grid-cols-3 gap-3">
                {nodes.filter(n => n.type === 'STORAGE' || n.type === 'CRYPTO' || n.type === 'CONTAINER').map((node) => {
                  const isSelected = selectedNode?.id === node.id;
                  const isImpacted = downstreamIds.includes(node.id);

                  return (
                    <div
                      key={node.id}
                      onClick={() => setSelectedNode(node)}
                      className={`p-3 rounded-lg border cursor-pointer transition-all ${
                        isSelected
                          ? 'bg-rose-950/60 border-rose-500 shadow-lg shadow-rose-500/20 ring-1 ring-rose-500'
                          : isImpacted
                          ? 'bg-amber-950/40 border-amber-600/70'
                          : 'bg-slate-900/90 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between text-xs font-semibold">
                        <span className="text-slate-200 truncate">{node.label}</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300">
                          {node.riskScore}
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-400 mt-1 flex items-center space-x-1.5">
                        <span className="text-purple-400">{node.type}</span>
                        <span>•</span>
                        <span className="truncate">{node.zone}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Node Blast Radius & Remediation Inspector */}
        <div className="lg:col-span-4 space-y-4">
          {selectedNode ? (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="border-b border-slate-800 pb-3">
                <div className="flex items-center space-x-2 text-xs">
                  <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-mono font-bold">
                    ID: {selectedNode.id}
                  </span>
                  <span className="text-slate-400">{selectedNode.provider || 'Multi-Cloud'}</span>
                </div>
                <h3 className="text-base font-bold text-white mt-1.5">{selectedNode.label}</h3>
                <p className="text-xs text-slate-400 mt-0.5">Asset Zone: {selectedNode.zone}</p>
              </div>

              {/* Blast Radius Stat Card */}
              <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400 font-medium">Downstream Blast Radius</span>
                  <span className="text-rose-400 font-bold font-mono text-sm">{downstreamIds.length} Assets</span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div 
                    className="bg-gradient-to-r from-amber-500 to-rose-500 h-full rounded-full"
                    style={{ width: `${Math.min(100, (downstreamIds.length / nodes.length) * 100)}%` }}
                  />
                </div>
                <p className="text-[11px] text-slate-400">
                  Compromise of this node provides access path to {downstreamIds.length} downstream components.
                </p>
              </div>

              {/* Reachable Assets List */}
              <div className="space-y-1.5">
                <span className="text-xs font-semibold text-slate-300">Reachable Downstream Nodes:</span>
                <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                  {downstreamIds.map(id => {
                    const nodeObj = nodes.find(n => n.id === id);
                    if (!nodeObj) return null;
                    return (
                      <div key={id} className="p-2 bg-slate-950 rounded border border-slate-800/80 text-xs flex items-center justify-between">
                        <span className="text-slate-300 truncate max-w-[180px]">{nodeObj.label}</span>
                        <span className="text-[10px] font-mono text-amber-400">{nodeObj.type}</span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Attack Vector Highlight */}
              <div className="p-3 rounded-lg bg-rose-950/30 border border-rose-900/60 text-xs text-rose-300 space-y-1">
                <div className="flex items-center space-x-1.5 font-semibold text-rose-200">
                  <Flame className="w-3.5 h-3.5 text-rose-400" />
                  <span>Toxic Combination Detected</span>
                </div>
                <p className="text-[11px] leading-relaxed text-rose-300/90">
                  This asset is part of the <strong>Internet-to-PII Exfiltration</strong> chain. Remediation of IAM boundary policy cuts the attack chain.
                </p>
              </div>
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-400 text-xs">
              Select an asset on the graph to inspect blast radius.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
