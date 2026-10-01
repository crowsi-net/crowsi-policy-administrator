#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ArtifactRole {
    Identity,
    Intent,
    PolicyDecision,
    EnforcementGrant,
    IsolationCommand,
    Coverage,
    PolicyInformation,
    RecoveryAuthorization,
    Receipt,
    CertificatePolicyDecision,
    CertificateExecutionGrant,
    CertificateApprovalEvidence,
    CertificateRevocationEvidence,
    CertificateAuthorityOutcomeEvidence,
    CertificateManagerCommitEvidence,
    CertificateManagerHandoffEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyScope {
    Identity {
        issuer: String,
        audience: String,
    },
    ProofKey(String),
    Policy(String),
    Audience(String),
    Observer(String),
    Provider(String),
    Approval {
        issuer: String,
        audience: String,
    },
    Revocation {
        issuer: String,
        audience: String,
    },
    AuthorityOutcome {
        issuer: String,
        audience: String,
        authority_id: String,
        security_domain: String,
        deployment_id: String,
    },
    ManagerCommit {
        issuer: String,
        audience: String,
        workload: String,
        security_domain: String,
        deployment_id: String,
    },
    ManagerHandoff {
        issuer: String,
        audience: String,
        workload: String,
        security_domain: String,
        deployment_id: String,
    },
}
