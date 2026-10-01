use crate::{ArtifactRole, KeyScope};

impl KeyScope {
    pub(crate) fn supports(&self, role: ArtifactRole) -> bool {
        matches!(
            (role, self),
            (ArtifactRole::Identity, Self::Identity { .. })
                | (ArtifactRole::Intent, Self::ProofKey(_))
                | (
                    ArtifactRole::PolicyDecision
                        | ArtifactRole::EnforcementGrant
                        | ArtifactRole::CertificatePolicyDecision
                        | ArtifactRole::CertificateExecutionGrant,
                    Self::Policy(_)
                )
                | (
                    ArtifactRole::IsolationCommand
                        | ArtifactRole::PolicyInformation
                        | ArtifactRole::RecoveryAuthorization,
                    Self::Audience(_)
                )
                | (ArtifactRole::Coverage, Self::Observer(_))
                | (ArtifactRole::Receipt, Self::Provider(_))
                | (
                    ArtifactRole::CertificateApprovalEvidence,
                    Self::Approval { .. }
                )
                | (
                    ArtifactRole::CertificateRevocationEvidence,
                    Self::Revocation { .. }
                )
                | (
                    ArtifactRole::CertificateAuthorityOutcomeEvidence,
                    Self::AuthorityOutcome { .. }
                )
                | (
                    ArtifactRole::CertificateManagerCommitEvidence,
                    Self::ManagerCommit { .. }
                )
                | (
                    ArtifactRole::CertificateManagerHandoffEvidence,
                    Self::ManagerHandoff { .. }
                )
        )
    }
}
