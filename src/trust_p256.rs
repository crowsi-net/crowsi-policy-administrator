use base64::{Engine, engine::general_purpose::STANDARD};
use crowsi_control_contracts::{
    CertificatePayloadV2, CertificateReceiptSignatureAlgorithmV2, CertificateReceiptSignatureV2,
};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use sha2::{Digest, Sha256};

use crate::{
    AdministratorError, ArtifactRole, KeyScope, Result, TrustedKeys,
    crypto::{bare_digest_bytes, valid_key_id},
};

pub(crate) struct TrustedP256Key {
    pub(crate) role: ArtifactRole,
    pub(crate) scope: KeyScope,
    pub(crate) key: VerifyingKey,
    pub(crate) key_version: String,
    pub(crate) spki_digest_sha256: String,
    pub(crate) purpose: String,
}

/// Closed metadata and public material for one P-256 receipt trust anchor.
pub struct P256TrustAnchorV2<'a> {
    pub key_id: &'a str,
    pub key_version: &'a str,
    pub spki_digest_sha256: &'a str,
    pub purpose: &'a str,
    pub role: ArtifactRole,
    pub scope: KeyScope,
    pub sec1: &'a [u8],
}

impl TrustedKeys {
    /// Adds one role-scoped P-256 receipt verifier from uncompressed SEC1 bytes.
    ///
    /// # Errors
    ///
    /// Rejects duplicate identity/material, unsupported scope, or metadata drift.
    pub fn insert_p256_sec1(&mut self, anchor: P256TrustAnchorV2<'_>) -> Result<()> {
        let key =
            VerifyingKey::from_sec1_bytes(anchor.sec1).map_err(|_| AdministratorError::Trust)?;
        let canonical = key.to_encoded_point(false);
        let digest = spki_digest(canonical.as_bytes());
        let duplicate = self
            .p256
            .values()
            .any(|item| item.key.to_encoded_point(false).as_bytes() == canonical.as_bytes());
        let valid = valid_key_id(anchor.key_id)
            && (8..=160).contains(&anchor.key_version.len())
            && !anchor.purpose.is_empty()
            && digest == anchor.spki_digest_sha256
            && anchor.scope.supports(anchor.role)
            && !self.ed25519.contains_key(anchor.key_id)
            && !self.p256.contains_key(anchor.key_id)
            && !duplicate;
        if !valid {
            return Err(AdministratorError::Trust);
        }
        self.p256.insert(
            anchor.key_id.into(),
            TrustedP256Key {
                role: anchor.role,
                scope: anchor.scope,
                key,
                key_version: anchor.key_version.into(),
                spki_digest_sha256: digest,
                purpose: anchor.purpose.into(),
            },
        );
        Ok(())
    }

    pub(crate) fn matches_p256_binding(
        &self,
        key_id: &str,
        key_version: &str,
        digest: &str,
        purpose: &str,
        role: ArtifactRole,
        scope: &KeyScope,
    ) -> bool {
        self.p256.get(key_id).is_some_and(|key| {
            key.role == role
                && key.scope == *scope
                && key.key_version == key_version
                && key.spki_digest_sha256 == digest
                && key.purpose == purpose
        })
    }

    pub(crate) fn verify_certificate_receipt<T: CertificatePayloadV2>(
        &self,
        role: ArtifactRole,
        scope: &KeyScope,
        purpose: &str,
        artifact: &T,
        signed: &CertificateReceiptSignatureV2,
    ) -> Result<()> {
        let digest = artifact.certificate_digest_sha256();
        let trusted = self
            .p256
            .get(&signed.key_id)
            .filter(|key| {
                key.role == role
                    && key.scope == *scope
                    && key.key_version == signed.key_version
                    && key.spki_digest_sha256 == signed.public_key_spki_sha256
                    && key.purpose == purpose
                    && signed.key_purpose == purpose
            })
            .ok_or(AdministratorError::Trust)?;
        if signed.algorithm != CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS
            || signed.digest_sha256 != digest
        {
            return Err(AdministratorError::Signature);
        }
        let bytes = STANDARD
            .decode(&signed.signature_base64)
            .map_err(|_| AdministratorError::Signature)?;
        if bytes.len() != 64 || STANDARD.encode(&bytes) != signed.signature_base64 {
            return Err(AdministratorError::Signature);
        }
        let signature = Signature::from_slice(&bytes).map_err(|_| AdministratorError::Signature)?;
        if signature.normalize_s().is_some() {
            return Err(AdministratorError::Signature);
        }
        trusted
            .key
            .verify_prehash(&bare_digest_bytes(&digest)?, &signature)
            .map_err(|_| AdministratorError::Signature)
    }
}

fn spki_digest(sec1: &[u8]) -> String {
    const PREFIX: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    let mut der = Vec::with_capacity(PREFIX.len() + sec1.len());
    der.extend_from_slice(&PREFIX);
    der.extend_from_slice(sec1);
    format!("{:x}", Sha256::digest(der))
}
