/**
 * AWS IAM Privilege Escalation Detection Engine
 * Implements graph-based detection across the 28 documented AWS IAM privilege escalation paths
 * (Rhino Security Labs / MITRE ATT&CK Cloud Matrix T1078, T1098, T1548).
 */

export const IAM_PRIVILEGE_ESCALATION_RULES = [
  {
    id: 'PRIV_ESC_01',
    name: 'CreateNewPolicyVersion',
    requiredActions: ['iam:CreatePolicyVersion'],
    severity: 'CRITICAL',
    mitreId: 'T1098',
    description: 'Create a new managed policy version with administrative permissions and set it as default.'
  },
  {
    id: 'PRIV_ESC_02',
    name: 'SetExistingDefaultPolicyVersion',
    requiredActions: ['iam:SetDefaultPolicyVersion'],
    severity: 'HIGH',
    mitreId: 'T1098',
    description: 'Switch the default version of an IAM policy to an older, more permissive version.'
  },
  {
    id: 'PRIV_ESC_03',
    name: 'CreateEC2WithExistingInstanceProfile',
    requiredActions: ['iam:PassRole', 'ec2:RunInstances'],
    severity: 'CRITICAL',
    mitreId: 'T1548.005',
    description: 'Launch an EC2 instance with an attached administrative instance profile and exfiltrate credentials.'
  },
  {
    id: 'PRIV_ESC_04',
    name: 'CreateAccessKey',
    requiredActions: ['iam:CreateAccessKey'],
    severity: 'HIGH',
    mitreId: 'T1098.001',
    description: 'Create programmatic API access keys for higher-privileged users without existing active keys.'
  },
  {
    id: 'PRIV_ESC_05',
    name: 'CreateLoginProfile',
    requiredActions: ['iam:CreateLoginProfile'],
    severity: 'HIGH',
    mitreId: 'T1098',
    description: 'Create a password login profile on an existing administrative user account lacking console access.'
  },
  {
    id: 'PRIV_ESC_06',
    name: 'UpdateLoginProfile',
    requiredActions: ['iam:UpdateLoginProfile'],
    severity: 'CRITICAL',
    mitreId: 'T1098',
    description: 'Reset password for an administrative user to take over their AWS Management Console session.'
  },
  {
    id: 'PRIV_ESC_07',
    name: 'AttachUserPolicy',
    requiredActions: ['iam:AttachUserPolicy'],
    severity: 'CRITICAL',
    mitreId: 'T1098',
    description: 'Directly attach AdministratorAccess managed policy to own or secondary user account.'
  },
  {
    id: 'PRIV_ESC_08',
    name: 'AttachGroupPolicy',
    requiredActions: ['iam:AttachGroupPolicy'],
    severity: 'CRITICAL',
    mitreId: 'T1098',
    description: 'Attach AdministratorAccess policy to an IAM group of which the attacker is a member.'
  },
  {
    id: 'PRIV_ESC_09',
    name: 'AttachRolePolicy',
    requiredActions: ['iam:AttachRolePolicy'],
    severity: 'CRITICAL',
    mitreId: 'T1098',
    description: 'Attach AdministratorAccess policy to an IAM role that can be assumed by the attacker.'
  },
  {
    id: 'PRIV_ESC_10',
    name: 'PutUserPolicy',
    requiredActions: ['iam:PutUserPolicy'],
    severity: 'CRITICAL',
    mitreId: 'T1098',
    description: 'Add an inline policy with Action: * and Resource: * directly to an IAM user.'
  },
  {
    id: 'PRIV_ESC_11',
    name: 'PutGroupPolicy',
    requiredActions: ['iam:PutGroupPolicy'],
    severity: 'CRITICAL',
    mitreId: 'T1098',
    description: 'Add an inline administrative policy to a group containing the current principal.'
  },
  {
    id: 'PRIV_ESC_12',
    name: 'PutRolePolicy',
    requiredActions: ['iam:PutRolePolicy'],
    severity: 'CRITICAL',
    mitreId: 'T1098',
    description: 'Add an inline administrative policy to an assumeable IAM role.'
  },
  {
    id: 'PRIV_ESC_13',
    name: 'AddUserToGroup',
    requiredActions: ['iam:AddUserToGroup'],
    severity: 'CRITICAL',
    mitreId: 'T1098',
    description: 'Add the current principal to an existing group possessing administrative privileges.'
  },
  {
    id: 'PRIV_ESC_14',
    name: 'UpdateAssumeRolePolicy',
    requiredActions: ['iam:UpdateAssumeRolePolicy', 'sts:AssumeRole'],
    severity: 'CRITICAL',
    mitreId: 'T1548.005',
    description: 'Modify trust policy of an admin role to permit assumption by current principal.'
  },
  {
    id: 'PRIV_ESC_15',
    name: 'PassRoleToLambdaAndInvoke',
    requiredActions: ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction'],
    severity: 'CRITICAL',
    mitreId: 'T1548.005',
    description: 'Deploy a Lambda function executing malicious code with an attached high-privilege execution role.'
  },
  {
    id: 'PRIV_ESC_16',
    name: 'PassRoleToLambdaWithEventSource',
    requiredActions: ['iam:PassRole', 'lambda:CreateFunction', 'lambda:CreateEventSourceMapping'],
    severity: 'CRITICAL',
    mitreId: 'T1548.005',
    description: 'Deploy Lambda and trigger execution via DynamoDB/Kinesis event source mapping.'
  },
  {
    id: 'PRIV_ESC_17',
    name: 'PassRoleToGlueDevEndpoint',
    requiredActions: ['iam:PassRole', 'glue:CreateDevEndpoint'],
    severity: 'HIGH',
    mitreId: 'T1548.005',
    description: 'Create an AWS Glue Development Endpoint associated with an administrative role.'
  },
  {
    id: 'PRIV_ESC_18',
    name: 'PassRoleToCloudFormation',
    requiredActions: ['iam:PassRole', 'cloudformation:CreateStack'],
    severity: 'CRITICAL',
    mitreId: 'T1548.005',
    description: 'Create a CloudFormation stack using an administrative service role to provision backdoor admins.'
  },
  {
    id: 'PRIV_ESC_19',
    name: 'PassRoleToDataPipeline',
    requiredActions: ['iam:PassRole', 'datapipeline:CreatePipeline', 'datapipeline:PutPipelineDefinition', 'datapipeline:ActivatePipeline'],
    severity: 'HIGH',
    mitreId: 'T1548.005',
    description: 'Create and activate an AWS Data Pipeline executing shell commands under a privileged role.'
  },
  {
    id: 'PRIV_ESC_20',
    name: 'PassRoleToCodeStar',
    requiredActions: ['iam:PassRole', 'codestar:CreateProject'],
    severity: 'HIGH',
    mitreId: 'T1548.005',
    description: 'Initialize a CodeStar project passing a privileged service role.'
  },
  {
    id: 'PRIV_ESC_21',
    name: 'PassRoleToSageMakerNotebook',
    requiredActions: ['iam:PassRole', 'sagemaker:CreateNotebookInstance'],
    severity: 'HIGH',
    mitreId: 'T1548.005',
    description: 'Create SageMaker Jupyter notebook with an attached administrative execution role.'
  },
  {
    id: 'PRIV_ESC_22',
    name: 'PassRoleToCodeBuild',
    requiredActions: ['iam:PassRole', 'codebuild:CreateProject', 'codebuild:StartBuild'],
    severity: 'HIGH',
    mitreId: 'T1548.005',
    description: 'Create and execute a CodeBuild container project under a privileged service role.'
  },
  {
    id: 'PRIV_ESC_23',
    name: 'PassRoleToSSMCommand',
    requiredActions: ['iam:PassRole', 'ssm:SendCommand'],
    severity: 'CRITICAL',
    mitreId: 'T1548.005',
    description: 'Execute arbitrary commands on managed EC2 instances configured with administrative instance profiles.'
  },
  {
    id: 'PRIV_ESC_24',
    name: 'PassRoleToBatchJob',
    requiredActions: ['iam:PassRole', 'batch:RegisterJobDefinition', 'batch:SubmitJob'],
    severity: 'HIGH',
    mitreId: 'T1548.005',
    description: 'Register and submit an AWS Batch container job running privileged operations.'
  },
  {
    id: 'PRIV_ESC_25',
    name: 'PassRoleToECS',
    requiredActions: ['iam:PassRole', 'ecs:RegisterTaskDefinition', 'ecs:RunTask'],
    severity: 'CRITICAL',
    mitreId: 'T1548.005',
    description: 'Run an ECS container task with a high-privilege task execution role.'
  },
  {
    id: 'PRIV_ESC_26',
    name: 'PassRoleToStepFunctions',
    requiredActions: ['iam:PassRole', 'states:CreateStateMachine', 'states:StartExecution'],
    severity: 'HIGH',
    mitreId: 'T1548.005',
    description: 'Create and run a Step Functions state machine executing API actions under a service role.'
  },
  {
    id: 'PRIV_ESC_27',
    name: 'PassRoleToEventBridge',
    requiredActions: ['iam:PassRole', 'events:PutRule', 'events:PutTargets'],
    severity: 'HIGH',
    mitreId: 'T1548.005',
    description: 'Configure EventBridge scheduled target invocations executing under a high-privilege role.'
  },
  {
    id: 'PRIV_ESC_28',
    name: 'PassRoleToAppSync',
    requiredActions: ['iam:PassRole', 'appsync:CreateGraphqlApi'],
    severity: 'MEDIUM',
    mitreId: 'T1548.005',
    description: 'Create GraphQL API datasource with privileged service role.'
  }
];

export class PrivilegeEscalationDetector {
  constructor(customRules = []) {
    this.rules = [...IAM_PRIVILEGE_ESCALATION_RULES, ...customRules];
  }

  /**
   * Evaluate a principal's effective permissions for privilege escalation vectors
   * @param {Object} principal - IAM principal details
   * @param {string} principal.arn - Principal ARN (user or role)
   * @param {Array<string>} principal.effectiveActions - Normalized list of permitted IAM actions (e.g. ['iam:*', 'ec2:RunInstances'])
   * @returns {Object} Analysis containing matched attack paths and risk score
   */
  analyzePrincipal(principal) {
    const grantedActions = new Set(
      (principal.effectiveActions || []).map(a => a.toLowerCase().trim())
    );

    const isWildcardAdmin = grantedActions.has('*') || grantedActions.has('*.*') || grantedActions.has('*:*');
    const matchedVectors = [];

    for (const rule of this.rules) {
      const hasAllActions = rule.requiredActions.every(req => {
        const reqLower = req.toLowerCase();
        if (isWildcardAdmin) return true;
        if (grantedActions.has(reqLower)) return true;

        // Check service wildcards (e.g., iam:* matches iam:CreatePolicyVersion)
        const [service] = reqLower.split(':');
        if (grantedActions.has(`${service}:*`)) return true;

        return false;
      });

      if (hasAllActions && !isWildcardAdmin) {
        matchedVectors.push({
          ruleId: rule.id,
          vectorName: rule.name,
          severity: rule.severity,
          mitreId: rule.mitreId,
          description: rule.description,
          requiredActions: rule.requiredActions,
          blastRadius: 'Direct elevation to AdministratorAccess (*:*)'
        });
      }
    }

    const criticalCount = matchedVectors.filter(v => v.severity === 'CRITICAL').length;
    const highCount = matchedVectors.filter(v => v.severity === 'HIGH').length;

    let riskLevel = 'LOW';
    if (isWildcardAdmin) riskLevel = 'FULL_ADMIN';
    else if (criticalCount > 0) riskLevel = 'CRITICAL';
    else if (highCount > 0) riskLevel = 'HIGH';

    return {
      principalArn: principal.arn,
      totalRulesEvaluated: this.rules.length,
      escalationPathsFound: matchedVectors.length,
      riskLevel,
      hasDirectEscalationToAdmin: matchedVectors.length > 0 || isWildcardAdmin,
      matchedVectors,
      timestamp: new Date().toISOString()
    };
  }
}

export default PrivilegeEscalationDetector;
if (typeof module !== 'undefined' && module.exports) {
  module.exports = PrivilegeEscalationDetector;
  module.exports.PrivilegeEscalationDetector = PrivilegeEscalationDetector;
  module.exports.IAM_PRIVILEGE_ESCALATION_RULES = IAM_PRIVILEGE_ESCALATION_RULES;
}
