use crowsi_control_contracts::{
    CanonicalPayloadV1, CoverageAssertionV1, EnforcementGrantV1, EnforcementReceiptV1,
    EnforcementReceiptV2, IsolationCommandV1, IsolationCommandV2, PolicyDecisionV1,
    PolicyInformationSnapshotV1, RecoveryAuthorizationV1, SecurityIntentV1, SignedDigestV1,
    VerifiedIdentityContextV1,
};
use crowsi_policy_administrator::Result;

use super::authorities::SimulationEd25519Authority;

pub fn sign<T>(authority: &SimulationEd25519Authority, value: &mut T) -> Result<()>
where
    T: CanonicalPayloadV1 + SignedArtifact,
{
    *value.signature_mut() = authority.sign(value)?;
    Ok(())
}

pub trait SignedArtifact {
    fn signature_mut(&mut self) -> &mut SignedDigestV1;
}

macro_rules! signed_artifact {
    ($($type:ty),+ $(,)?) => {$(
        impl SignedArtifact for $type {
            fn signature_mut(&mut self) -> &mut SignedDigestV1 {
                &mut self.signed
            }
        }
    )+};
}

signed_artifact!(
    VerifiedIdentityContextV1,
    SecurityIntentV1,
    CoverageAssertionV1,
    PolicyDecisionV1,
    EnforcementGrantV1,
    IsolationCommandV1,
    IsolationCommandV2,
    EnforcementReceiptV1,
    EnforcementReceiptV2,
    PolicyInformationSnapshotV1,
    RecoveryAuthorizationV1,
);
