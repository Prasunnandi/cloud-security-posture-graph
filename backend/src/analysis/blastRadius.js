/**
 * Cloud Security Posture Graph - Transitive Blast Radius Simulator
 * Evaluates lateral movement propagation across Security Groups, VPC peerings,
 * and IAM instance profile permissions when a cloud compute instance is compromised.
 */

export const BLAST_RISK_TIERS = {
  CATASTROPHIC: 'CATASTROPHIC', // Direct or transitive path to production database or admin credentials
  HIGH: 'HIGH',                 // Multi-instance lateral movement across VPC/security groups
  MEDIUM: 'MEDIUM',             // Limited to same subnet / non-sensitive services
  LOW: 'LOW'                    // Isolated bastion or read-only edge node
};

export class CloudBlastRadiusSimulator {
  /**
   * @param {Object} topology - Cloud infrastructure graph
   * @param {Array<Object>} topology.instances - Compute nodes [{ id, name, subnetId, securityGroups: [], iamRoleArn, dataAccess: [] }]
   * @param {Array<Object>} topology.securityGroups - Security groups [{ id, name, ingressRules: [{ fromPort, toPort, protocol, sourceSgId, sourceCidr }] }]
   * @param {Array<Object>} [topology.dataStores] - Databases & S3 buckets [{ id, name, type, securityGroups: [], isProduction: boolean }]
   * @param {Array<Object>} [topology.vpcPeerings] - VPC peering connections [{ vpcA, vpcB, bidirectional: boolean }]
   */
  constructor(topology = {}) {
    this.instances = topology.instances || [];
    this.securityGroups = topology.securityGroups || [];
    this.dataStores = topology.dataStores || [];
    this.vpcPeerings = topology.vpcPeerings || [];

    this._indexTopology();
  }

  _indexTopology() {
    this.instanceMap = new Map(this.instances.map((i) => [i.id, i]));
    this.sgMap = new Map(this.securityGroups.map((sg) => [sg.id, sg]));
    this.dataStoreMap = new Map(this.dataStores.map((ds) => [ds.id, ds]));
  }

  /**
   * Test whether source security groups can reach target security groups based on ingress rules
   */
  canReachNetwork(sourceSgIds = [], targetSgIds = []) {
    for (const targetSgId of targetSgIds) {
      const targetSg = this.sgMap.get(targetSgId);
      if (!targetSg || !targetSg.ingressRules) continue;

      for (const rule of targetSg.ingressRules) {
        // Direct SG-to-SG reference
        if (rule.sourceSgId && sourceSgIds.includes(rule.sourceSgId)) {
          return { allowed: true, port: rule.fromPort || 'ALL', protocol: rule.protocol || 'TCP' };
        }
        // Universal open 0.0.0.0/0
        if (rule.sourceCidr === '0.0.0.0/0') {
          return { allowed: true, port: rule.fromPort || 'ALL', protocol: rule.protocol || 'TCP' };
        }
      }
    }
    return { allowed: false };
  }

  /**
   * Simulate transitive compromise blast radius starting from an initial compromised instance
   * @param {string} initialInstanceId - ID of compromised compute instance
   * @param {number} [maxDepth=6] - Maximum traversal hop depth
   * @returns {Object} Comprehensive blast radius report
   */
  simulate(initialInstanceId, maxDepth = 6) {
    const rootInstance = this.instanceMap.get(initialInstanceId);
    if (!rootInstance) {
      throw new Error(`Instance "${initialInstanceId}" not found in topology.`);
    }

    // Queue for BFS traversal: { nodeId, nodeType, path: [], depth: number }
    const queue = [
      {
        nodeId: rootInstance.id,
        nodeType: 'INSTANCE',
        name: rootInstance.name || rootInstance.id,
        path: [rootInstance.id],
        depth: 0,
        compromisedVia: 'PATIENT_ZERO'
      }
    ];

    const visitedNodes = new Set([rootInstance.id]);
    const compromisedInstances = [];
    const compromisedDataStores = [];
    const attackPaths = [];

    while (queue.length > 0) {
      const current = queue.shift();

      if (current.nodeType === 'INSTANCE') {
        const inst = this.instanceMap.get(current.nodeId);
        compromisedInstances.push({
          instanceId: inst.id,
          name: inst.name,
          depth: current.depth,
          securityGroups: inst.securityGroups,
          iamRoleArn: inst.iamRoleArn,
          compromisedVia: current.compromisedVia
        });

        // 1. Check data access via IAM role or explicit access
        if (inst.dataAccess && Array.isArray(inst.dataAccess)) {
          for (const dsId of inst.dataAccess) {
            const ds = this.dataStoreMap.get(dsId);
            if (ds && !visitedNodes.has(ds.id)) {
              visitedNodes.add(ds.id);
              const dsPath = [...current.path, ds.id];
              attackPaths.push({
                targetId: ds.id,
                targetName: ds.name,
                targetType: 'DATASTORE',
                isProduction: Boolean(ds.isProduction),
                hops: dsPath.length - 1,
                path: dsPath
              });
              compromisedDataStores.push({
                dataStoreId: ds.id,
                name: ds.name,
                type: ds.type || 'DATABASE',
                isProduction: Boolean(ds.isProduction),
                exposedViaInstance: inst.id,
                hops: current.depth + 1
              });
            }
          }
        }

        // 2. Check network lateral movement to other instances
        if (current.depth < maxDepth) {
          for (const candidate of this.instances) {
            if (visitedNodes.has(candidate.id)) continue;

            const access = this.canReachNetwork(inst.securityGroups, candidate.securityGroups);
            if (access.allowed) {
              visitedNodes.add(candidate.id);
              const nextHop = {
                nodeId: candidate.id,
                nodeType: 'INSTANCE',
                name: candidate.name,
                path: [...current.path, candidate.id],
                depth: current.depth + 1,
                compromisedVia: `Network SG ingress port ${access.port} (${access.protocol}) from ${inst.id}`
              };
              queue.push(nextHop);
              attackPaths.push({
                targetId: candidate.id,
                targetName: candidate.name,
                targetType: 'INSTANCE',
                hops: nextHop.path.length - 1,
                path: nextHop.path,
                rule: access
              });
            }
          }
        }

        // 3. Check network lateral movement directly to data stores with SG access
        for (const ds of this.dataStores) {
          if (visitedNodes.has(ds.id)) continue;

          const access = this.canReachNetwork(inst.securityGroups, ds.securityGroups);
          if (access.allowed) {
            visitedNodes.add(ds.id);
            const dsPath = [...current.path, ds.id];
            attackPaths.push({
              targetId: ds.id,
              targetName: ds.name,
              targetType: 'DATASTORE',
              isProduction: Boolean(ds.isProduction),
              hops: dsPath.length - 1,
              path: dsPath
            });
            compromisedDataStores.push({
              dataStoreId: ds.id,
              name: ds.name,
              type: ds.type || 'DATABASE',
              isProduction: Boolean(ds.isProduction),
              exposedViaInstance: inst.id,
              hops: current.depth + 1
            });
          }
        }
      }
    }

    // Determine Blast Radius Score (0 to 100)
    let score = (compromisedInstances.length - 1) * 15;
    const hasProdDb = compromisedDataStores.some((ds) => ds.isProduction);
    if (hasProdDb) score += 50;
    score += compromisedDataStores.length * 20;
    const blastRadiusScore = Math.min(100, Math.max(10, score));

    let riskTier = BLAST_RISK_TIERS.LOW;
    if (hasProdDb || blastRadiusScore >= 80) riskTier = BLAST_RISK_TIERS.CATASTROPHIC;
    else if (blastRadiusScore >= 50) riskTier = BLAST_RISK_TIERS.HIGH;
    else if (blastRadiusScore >= 25) riskTier = BLAST_RISK_TIERS.MEDIUM;

    return {
      patientZero: {
        id: rootInstance.id,
        name: rootInstance.name,
        securityGroups: rootInstance.securityGroups,
        iamRoleArn: rootInstance.iamRoleArn
      },
      blastRadiusScore,
      riskTier,
      totalCompromisedAssets: compromisedInstances.length + compromisedDataStores.length,
      compromisedInstancesCount: compromisedInstances.length,
      compromisedDataStoresCount: compromisedDataStores.length,
      compromisedInstances,
      compromisedDataStores,
      attackPaths,
      remediationRecommendation:
        riskTier === BLAST_RISK_TIERS.CATASTROPHIC
          ? `URGENT: Isolate ${rootInstance.id} immediately. Restrict SG ingress rules and revoke IAM instance credentials with access to production data stores.`
          : riskTier === BLAST_RISK_TIERS.HIGH
          ? `HIGH: Segment security groups to prevent lateral movement across subnet tiers.`
          : 'Normal isolation posture maintained.'
    };
  }
}

// Dual ESM & CommonJS compatibility
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    BLAST_RISK_TIERS,
    CloudBlastRadiusSimulator
  };
}

export default CloudBlastRadiusSimulator;
