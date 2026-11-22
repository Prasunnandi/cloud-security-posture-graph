import express from 'express';
import cors from 'cors';
import { graphNodes, graphEdges, securityFindings } from './data.js';

const app = express();
const PORT = process.env.PORT || 8000;

app.use(cors());
app.use(express.json());

let findings = [...securityFindings];

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'cloud-security-posture-graph', timestamp: new Date().toISOString() });
});

// Graph Topology & Attack Edges
app.get('/api/graph', (req, res) => {
  res.json({
    nodes: graphNodes,
    edges: graphEdges,
    toxicCombinationsCount: graphEdges.filter(e => e.toxic).length,
    criticalPaths: 3
  });
});

// Security Findings list
app.get('/api/findings', (req, res) => {
  res.json({
    findings,
    summary: {
      total: findings.length,
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      toxicCombinations: findings.filter(f => f.toxicCombination).length,
      resolved: findings.filter(f => f.status === 'RESOLVED').length
    }
  });
});

// Remediate Finding
app.post('/api/findings/:id/remediate', (req, res) => {
  const { id } = req.params;
  const finding = findings.find(f => f.id === id);
  if (!finding) {
    return res.status(404).json({ error: 'Finding not found' });
  }

  finding.status = 'RESOLVED';
  res.json({
    message: `Remediation applied successfully for ${id}`,
    finding,
    terraformPr: `https://github.com/enterprise-cloud/infrastructure/pull/${Math.floor(100 + Math.random() * 900)}`
  });
});

// Blast Radius Simulation
app.get('/api/blast-radius/:nodeId', (req, res) => {
  const { nodeId } = req.params;
  const visited = new Set();
  const queue = [nodeId];

  while (queue.length > 0) {
    const curr = queue.shift();
    if (!visited.has(curr)) {
      visited.add(curr);
      const outgoing = graphEdges.filter(e => e.source === curr);
      for (const edge of outgoing) {
        if (!visited.has(edge.target)) {
          queue.push(edge.target);
        }
      }
    }
  }

  const impactedNodes = graphNodes.filter(n => visited.has(n.id));
  res.json({
    origin: nodeId,
    blastRadiusCount: impactedNodes.length,
    impactedAssets: impactedNodes
  });
});

app.listen(PORT, () => {
  console.log(`Cloud Security Posture Graph API running on port ${PORT}`);
});
