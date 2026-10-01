use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};

use crate::{
    AuthenticatedCertificateManagerChannelV2, CertificateLeaseSignerIdentityV2,
    CertificateLeaseSignerOutcomeV2, CertificateLeaseSignerV2, CertificatePolicyAdministratorV2,
    certificate_test_handoff_v2,
    certificate_test_keys_v2::{LEASE_SIGNER_SEED, policy},
    crypto::bare_digest_bytes,
};
use crowsi_control_contracts::SignedCertificateExecutionAuthorizationV2;

#[derive(Clone, Copy)]
pub(crate) enum Mode {
    Signed,
    DefinitelyNotSigned,
    Unknown,
}

pub(crate) fn sign_and_release(
    administrator: &mut CertificatePolicyAdministratorV2,
    channel: &AuthenticatedCertificateManagerChannelV2,
    jti: &str,
) -> SignedCertificateExecutionAuthorizationV2 {
    administrator
        .sign_certificate_execution_v2(channel, jti, &mut TestSigner::signed())
        .unwrap();
    let signed = administrator
        .release_signed_certificate_execution_v2(channel, jti)
        .unwrap();
    certificate_test_handoff_v2::accept_released(administrator, channel, &signed);
    signed
}

pub(crate) struct TestSigner {
    sign: Mode,
    recover: Mode,
}

impl TestSigner {
    pub(crate) const fn signed() -> Self {
        Self {
            sign: Mode::Signed,
            recover: Mode::Signed,
        }
    }

    pub(crate) const fn unknown_then_signed() -> Self {
        Self {
            sign: Mode::Unknown,
            recover: Mode::Signed,
        }
    }

    pub(crate) const fn definitely_not_signed() -> Self {
        Self {
            sign: Mode::DefinitelyNotSigned,
            recover: Mode::DefinitelyNotSigned,
        }
    }
}

impl CertificateLeaseSignerV2 for TestSigner {
    fn identity(&self) -> CertificateLeaseSignerIdentityV2 {
        let policy = policy();
        CertificateLeaseSignerIdentityV2 {
            key_id: policy.authorization_verifier_key_id,
            key_version: policy.authorization_signer_key_version,
            public_key_digest_sha256: policy.authorization_signer_public_key_digest_sha256,
            public_key_spki_sha256: policy.authorization_signer_public_key_spki_sha256,
            workload: policy.authorization_signer_workload,
            purpose: policy.authorization_signer_purpose,
        }
    }

    fn sign_once(&mut self, _: &str, digest: &str) -> CertificateLeaseSignerOutcomeV2 {
        outcome(self.sign, digest)
    }

    fn recover(&mut self, _: &str, digest: &str) -> CertificateLeaseSignerOutcomeV2 {
        outcome(self.recover, digest)
    }
}

fn outcome(mode: Mode, digest: &str) -> CertificateLeaseSignerOutcomeV2 {
    match mode {
        Mode::Signed => {
            let key = SigningKey::from_bytes(&[LEASE_SIGNER_SEED; 32]);
            let signature = key.sign(&bare_digest_bytes(digest).unwrap());
            CertificateLeaseSignerOutcomeV2::Signed {
                signature_base64: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            }
        }
        Mode::DefinitelyNotSigned => CertificateLeaseSignerOutcomeV2::DefinitelyNotSigned,
        Mode::Unknown => CertificateLeaseSignerOutcomeV2::OutcomeUnknown,
    }
}
