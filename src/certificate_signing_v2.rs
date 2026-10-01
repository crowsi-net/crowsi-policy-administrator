use crate::{
    AuthenticatedCertificateManagerChannelV2, CertificatePolicyAdministratorV2, Result,
    certificate_execution_v2, certificate_signing_state_v2, certificate_signing_store_v2,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateLeaseSignerIdentityV2 {
    pub key_id: String,
    pub key_version: String,
    pub public_key_digest_sha256: String,
    pub public_key_spki_sha256: String,
    pub workload: String,
    pub purpose: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateLeaseSignerOutcomeV2 {
    Signed { signature_base64: String },
    DefinitelyNotSigned,
    OutcomeUnknown,
}

pub trait CertificateLeaseSignerV2 {
    fn identity(&self) -> CertificateLeaseSignerIdentityV2;

    fn sign_once(
        &mut self,
        attempt_id: &str,
        lease_digest_sha256: &str,
    ) -> CertificateLeaseSignerOutcomeV2;

    fn recover(
        &mut self,
        attempt_id: &str,
        lease_digest_sha256: &str,
    ) -> CertificateLeaseSignerOutcomeV2;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateSigningProgressV2 {
    Ready {
        attempt_id: String,
        lease_digest_sha256: String,
    },
    DefinitelyNotSigned {
        attempt_id: String,
        lease_digest_sha256: String,
    },
    OutcomeUnknown {
        attempt_id: String,
        lease_digest_sha256: String,
    },
}

impl CertificatePolicyAdministratorV2 {
    /// Prepares and signs one exact durable lease without releasing it.
    ///
    /// # Errors
    ///
    /// Rejects untrusted signer identity, replay, expiry, or ledger drift.
    pub fn sign_certificate_execution_v2<S: CertificateLeaseSignerV2>(
        &mut self,
        _channel: &AuthenticatedCertificateManagerChannelV2,
        authorization_jti: &str,
        signer: &mut S,
    ) -> Result<CertificateSigningProgressV2> {
        let identity = signer.identity();
        let prepared = certificate_execution_v2::prepare(self, authorization_jti, &identity)?;
        if prepared.existing {
            return Ok(prepared.progress);
        }
        let outcome = signer.sign_once(&prepared.attempt_id, &prepared.lease_digest_sha256);
        certificate_signing_store_v2::store(self, prepared, outcome)
    }

    /// Recovers a signer response that was ambiguous or lost before storage.
    ///
    /// # Errors
    ///
    /// Rejects signer substitution, non-recoverable state, or ledger drift.
    pub fn recover_certificate_execution_signature_v2<S: CertificateLeaseSignerV2>(
        &mut self,
        _channel: &AuthenticatedCertificateManagerChannelV2,
        authorization_jti: &str,
        signer: &mut S,
    ) -> Result<CertificateSigningProgressV2> {
        let prepared = certificate_signing_state_v2::load_recoverable(
            self,
            authorization_jti,
            &signer.identity(),
        )?;
        let outcome = signer.recover(&prepared.attempt_id, &prepared.lease_digest_sha256);
        certificate_signing_store_v2::store(self, prepared, outcome)
    }
}
