import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import Navbar from './components/Navbar';
import AttackPathGraphView from './pages/AttackPathGraphView';
import CspmFindingsView from './pages/CspmFindingsView';

const INITIAL_NODES = [
  { id: "internet", label: "Public Internet (0.0.0.0/0)", type: "EXTERNAL", riskScore: 100, zone: "External Ingress" },
  { id: "bastion-ec2", label: "EC2 Bastion Host (i-0382910)", type: "COMPUTE", riskScore: 85, zone: "DMZ VPC", provider: "AWS" },
  { id: "lambda-worker", label: "Lambda: ETLDataProcessor", type: "SERVERLESS", riskScore: 78, zone: "App Subnet", provider: "AWS" },
  { id: "iam-dev-role", label: "IAM Role: LambdaExecutionDevRole", type: "IAM_ROLE", riskScore: 95, zone: "IAM Control Plane", provider: "AWS" },
  { id: "iam-admin-policy", label: "IAM Policy: AdministratorAccess", type: "IAM_POLICY", riskScore: 99, zone: "IAM Control Plane", provider: "AWS" },
  { id: "s3-pii-bucket", label: "S3 Bucket: prod-customer-pii-backups", type: "STORAGE", riskScore: 98, zone: "Data Store", provider: "AWS" },
  { id: "kms-master-key", label: "KMS Key: alias/prod-pii-cmk", type: "CRYPTO", riskScore: 90, zone: "Security Core", provider: "AWS" },
  { id: "k8s-prod-eks", label: "EKS Cluster: prod-core-eks", type: "CONTAINER", riskScore: 94, zone: "Container Fabric", provider: "AWS" },
  { id: "azure-key-vault", label: "KeyVault: kv-prod-secrets", type: "CRYPTO", riskScore: 65, zone: "Azure WestUS", provider: "Azure" },
  { id: "gcp-storage", label: "GCS Bucket: gcp-fintech-ledger", type: "STORAGE", riskScore: 92, zone: "GCP us-central1", provider: "GCP" }
];

const INITIAL_EDGES = [
  { source: "internet", target: "bastion-ec2", relationship: "PORT_22_OPEN_INGRESS", severity: "HIGH" },
  { source: "bastion-ec2", target: "lambda-worker", relationship: "INVOKES_UNRESTRICTED", severity: "HIGH" },
  { source: "lambda-worker", target: "iam-dev-role", relationship: "ATTACHED_INSTANCE_PROFILE", severity: "CRITICAL" },
  { source: "iam-dev-role", target: "iam-admin-policy", relationship: "CAN_PASSROLE_AND_CREATE_ADMIN", severity: "CRITICAL", toxic: true },
  { source: "iam-admin-policy", target: "s3-pii-bucket", relationship: "FULL_OBJECT_EXFILTRATION", severity: "CRITICAL", toxic: true },
  { source: "internet", target: "s3-pii-bucket", relationship: "PUBLIC_ACL_ALLUSERS_READ", severity: "CRITICAL", toxic: true },
  { source: "s3-pii-bucket", target: "kms-master-key", relationship: "WILDCARD_DECRYPT_GRANTED", severity: "CRITICAL" },
  { source: "internet", target: "k8s-prod-eks", relationship: "ANONYMOUS_K8S_API_ACCESS", severity: "CRITICAL", toxic: true }
];

const INITIAL_FINDINGS = [
  {
    id: "CSPM-AWS-1001",
    provider: "AWS",
    resourceType: "aws_iam_role",
    resourceArn: "arn:aws:iam::129840192841:role/LambdaExecutionDevRole",
    severity: "CRITICAL",
    cisBenchmarkId: "CIS-AWS-1.16",
    attackVector: "Privilege Escalation via iam:PassRole + lambda:CreateFunction -> AdministratorAccess",
    toxicCombination: true,
    blastRadiusNodes: 24,
    remediationCode: `resource "aws_iam_role_policy" "restrict_passrole" {\n  name = "EnforcePassRoleBoundaries"\n  role = aws_iam_role.lambda_dev.id\n  policy = jsonencode({\n    Version = "2012-10-17"\n    Statement = [\n      {\n        Effect   = "Deny"\n        Action   = "iam:PassRole"\n        Resource = "*"\n      }\n    ]\n  })\n}`,
    status: "OPEN"
  },
  {
    id: "CSPM-AWS-1002",
    provider: "AWS",
    resourceType: "aws_s3_bucket",
    resourceArn: "arn:aws:s3:::prod-customer-pii-backups-2026",
    severity: "CRITICAL",
    cisBenchmarkId: "CIS-AWS-2.1.1",
    attackVector: "Public S3 Bucket ACL (AllUsers READ) paired with Wildcard KMS Decrypt Key",
    toxicCombination: true,
    blastRadiusNodes: 18,
    remediationCode: `resource "aws_s3_bucket_public_access_block" "pii_block" {\n  bucket = aws_s3_bucket.pii_backups.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}`,
    status: "OPEN"
  },
  {
    id: "CSPM-AWS-1003",
    provider: "AWS",
    resourceType: "aws_security_group",
    resourceArn: "arn:aws:ec2:us-east-1:129840192841:security-group/sg-09a2b8e",
    severity: "HIGH",
    cisBenchmarkId: "CIS-AWS-5.2",
    attackVector: "Inbound Port 22 (SSH) open to 0.0.0.0/0 on Bastion attached to Production VPC",
    toxicCombination: false,
    blastRadiusNodes: 12,
    remediationCode: `ingress {\n  description = "Internal VPN CIDR only"\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.240.0.0/16"]\n}`,
    status: "IN_REVIEW"
  },
  {
    id: "CSPM-AWS-1004",
    provider: "AWS",
    resourceType: "aws_eks_cluster",
    resourceArn: "arn:aws:eks:us-east-1:129840192841:cluster/prod-core-eks",
    severity: "CRITICAL",
    cisBenchmarkId: "CIS-EKS-1.2",
    attackVector: "Kubernetes API server endpoint publicly accessible with anonymous auth enabled",
    toxicCombination: true,
    blastRadiusNodes: 35,
    remediationCode: `vpc_config {\n  endpoint_private_access = true\n  endpoint_public_access  = false\n  public_access_cidrs     = []\n}`,
    status: "OPEN"
  },
  {
    id: "CSPM-GCP-1006",
    provider: "GCP",
    resourceType: "google_storage_bucket",
    resourceArn: "gs://gcp-fintech-ledger-exports",
    severity: "CRITICAL",
    cisBenchmarkId: "CIS-GCP-5.1",
    attackVector: "Uniform bucket-level access disabled allowing legacy public ACL objects",
    toxicCombination: true,
    blastRadiusNodes: 16,
    remediationCode: `resource "google_storage_bucket" "ledger" {\n  name                     = "gcp-fintech-ledger-exports"\n  uniform_bucket_level_access = true\n  force_destroy            = false\n}`,
    status: "OPEN"
  }
];

export default function App() {
  const [activeTab, setActiveTab] = useState('graph');
  const [nodes, setNodes] = useState(INITIAL_NODES);
  const [edges, setEdges] = useState(INITIAL_EDGES);
  const [findings, setFindings] = useState(INITIAL_FINDINGS);
  const [loading, setLoading] = useState(false);

  const handleRefresh = () => {
    setLoading(true);
    setTimeout(() => {
      setLoading(false);
    }, 500);
  };

  const handleRemediate = (id) => {
    setFindings(prev => prev.map(f => {
      if (f.id === id) {
        return { ...f, status: 'RESOLVED' };
      }
      return f;
    }));
  };

  const summary = {
    total: findings.length,
    critical: findings.filter(f => f.severity === 'CRITICAL' && f.status !== 'RESOLVED').length,
    high: findings.filter(f => f.severity === 'HIGH' && f.status !== 'RESOLVED').length,
    toxicCombinations: findings.filter(f => f.toxicCombination && f.status !== 'RESOLVED').length,
    resolved: findings.filter(f => f.status === 'RESOLVED').length
  };

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden font-sans">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Navbar 
          onRefresh={handleRefresh} 
          loading={loading} 
          summary={summary} 
        />

        <main className="flex-1 overflow-y-auto p-6">
          {activeTab === 'graph' ? (
            <AttackPathGraphView 
              nodes={nodes} 
              edges={edges} 
            />
          ) : (
            <CspmFindingsView 
              findings={findings} 
              onRemediate={handleRemediate} 
            />
          )}
        </main>
      </div>
    </div>
  );
}
