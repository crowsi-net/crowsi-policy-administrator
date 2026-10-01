use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_control_contracts::{
    CanonicalPayloadV1, CertificateDetachedSignatureV2, CertificatePayloadV2,
    CertificateSignatureAlgorithmV2, SignatureAlgorithm, SignedDigestV1,
};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::{
    AdministratorError, Result,
    crypto::{bare_digest_bytes, digest_bytes, valid_key_id},
    trust_model::{ArtifactRole, KeyScope},
};

pub(crate) struct TrustedKey {
    role: ArtifactRole,
    scope: KeyScope,
    key: VerifyingKey,
}

#[derive(Default)]
pub struct TrustedKeys {
    pub(crate) ed25519: BTreeMap<String, TrustedKey>,
    pub(crate) p256: BTreeMap<String, crate::trust_p256::TrustedP256Key>,
}

impl TrustedKeys {
    pub(crate) fn contains_ed25519_key(&self, bytes: &[u8; 32]) -> bool {
        self.ed25519
            .values()
            .any(|trusted| trusted.key.as_bytes() == bytes)
    }

    /// Adds one role-scoped Ed25519 verifier.
    ///
    /// # Errors
    ///
    /// Rejects duplicate identifiers or key material, weak keys, and a scope
    /// that is invalid for the artifact role.
    pub fn insert_ed25519(
        &mut self,
        key_id: &str,
        role: ArtifactRole,
        scope: KeyScope,
        bytes: [u8; 32],
    ) -> Result<()> {
        if !valid_key_id(key_id)
            || self.ed25519.contains_key(key_id)
            || self.p256.contains_key(key_id)
            || !scope.supports(role)
        {
            return Err(AdministratorError::Trust);
        }
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| AdministratorError::Trust)?;
        if key.is_weak()
            || self
                .ed25519
                .values()
                .any(|trusted| trusted.key.as_bytes() == key.as_bytes())
        {
            return Err(AdministratorError::Trust);
        }
        self.ed25519
            .insert(key_id.to_owned(), TrustedKey { role, scope, key });
        Ok(())
    }

    pub(crate) fn verify<T: CanonicalPayloadV1>(
        &self,
        role: ArtifactRole,
        scope: &KeyScope,
        artifact: &T,
        signed: &SignedDigestV1,
    ) -> Result<()> {
        artifact
            .validate_payload_digest()
            .map_err(|_| AdministratorError::Signature)?;
        if signed.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(AdministratorError::Trust);
        }
        let trusted = self
            .ed25519
            .get(&signed.key_id)
            .filter(|trusted| trusted.role == role && trusted.scope == *scope)
            .ok_or(AdministratorError::Trust)?;
        let encoded = URL_SAFE_NO_PAD
            .decode(&signed.signature)
            .map_err(|_| AdministratorError::Signature)?;
        let bytes: [u8; 64] = encoded
            .try_into()
            .map_err(|_| AdministratorError::Signature)?;
        trusted
            .key
            .verify_strict(
                &digest_bytes(&signed.digest)?,
                &Signature::from_bytes(&bytes),
            )
            .map_err(|_| AdministratorError::Signature)
    }

    pub(crate) fn verify_certificate<T: CertificatePayloadV2>(
        &self,
        role: ArtifactRole,
        scope: &KeyScope,
        artifact: &T,
        signed: &CertificateDetachedSignatureV2,
    ) -> Result<()> {
        let digest = artifact.certificate_digest_sha256();
        if signed.algorithm != CertificateSignatureAlgorithmV2::Ed25519
            || signed.digest_sha256 != digest
        {
            return Err(AdministratorError::Signature);
        }
        let trusted = self
            .ed25519
            .get(&signed.key_id)
            .filter(|trusted| trusted.role == role && trusted.scope == *scope)
            .ok_or(AdministratorError::Trust)?;
        let encoded = URL_SAFE_NO_PAD
            .decode(&signed.signature_base64)
            .map_err(|_| AdministratorError::Signature)?;
        let bytes: [u8; 64] = encoded
            .try_into()
            .map_err(|_| AdministratorError::Signature)?;
        trusted
            .key
            .verify_strict(&bare_digest_bytes(&digest)?, &Signature::from_bytes(&bytes))
            .map_err(|_| AdministratorError::Signature)
    }
}
