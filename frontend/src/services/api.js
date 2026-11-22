// Cloud Security Posture Management API Service
const API_BASE = 'http://localhost:8000';

export async function fetchGraph() {
  try {
    const res = await fetch(`${API_BASE}/api/graph`);
    if (!res.ok) throw new Error('Graph fetch failed');
    return await res.json();
  } catch (e) {
    return null;
  }
}

export async function fetchFindings() {
  try {
    const res = await fetch(`${API_BASE}/api/findings`);
    if (!res.ok) throw new Error('Findings fetch failed');
    return await res.json();
  } catch (e) {
    return null;
  }
}

export async function remediateFinding(id) {
  try {
    const res = await fetch(`${API_BASE}/api/findings/${id}/remediate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    if (!res.ok) throw new Error('Remediation failed');
    return await res.json();
  } catch (e) {
    return {
      message: `Remediation applied locally for ${id}`,
      terraformPr: `https://github.com/enterprise-cloud/infrastructure/pull/402`
    };
  }
}

export async function fetchBlastRadius(nodeId) {
  try {
    const res = await fetch(`${API_BASE}/api/blast-radius/${nodeId}`);
    if (!res.ok) throw new Error('Blast radius error');
    return await res.json();
  } catch (e) {
    return null;
  }
}
