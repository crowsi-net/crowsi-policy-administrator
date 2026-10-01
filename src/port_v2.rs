use crowsi_control_contracts::EnforcementReceiptV2;

use crate::{AdministratorError, PepExecutionLeaseV2, Result};

pub trait EnforcementPointV2 {
    /// Applies one exact target, version, and latest-fence compare-and-swap.
    ///
    /// The PEP must validate the closed lease, verify the command signature
    /// against its own allowlist, and reject a fence not greater than its
    /// durable latest fence. It persists a greater fence before provider
    /// mutation and never rolls it back when the separate resource-version CAS
    /// is definitively rejected.
    ///
    /// # Errors
    ///
    /// Returns an uncertain result when no definitive signed receipt exists.
    fn compare_and_swap(
        &mut self,
        lease: &PepExecutionLeaseV2,
    ) -> std::result::Result<EnforcementReceiptV2, PepExecutionUncertainV2>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PepExecutionUncertainV2 {
    evidence_digest: String,
}

impl PepExecutionUncertainV2 {
    /// Creates a fail-closed result for a provider call without a definitive receipt.
    ///
    /// # Errors
    ///
    /// Rejects evidence that is not a lowercase SHA-256 digest.
    pub fn new(evidence_digest: &str) -> Result<Self> {
        if valid_digest(evidence_digest) {
            Ok(Self {
                evidence_digest: evidence_digest.to_owned(),
            })
        } else {
            Err(AdministratorError::Contract(
                "evidence_digest: invalid SHA-256 digest".into(),
            ))
        }
    }

    #[must_use]
    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
