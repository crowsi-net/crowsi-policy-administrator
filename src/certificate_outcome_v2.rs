use rusqlite::params;

use crate::{
    AdministratorError, AuthenticatedCertificateManagerChannelV2, CertificateCompletionInputV2,
    CertificateCompletionReceiptV2, CertificatePolicyAdministratorV2, Result,
};

impl CertificatePolicyAdministratorV2 {
    /// Locks an ambiguous manager handoff until explicit reconciliation.
    ///
    /// # Errors
    ///
    /// Rejects malformed evidence or a non-executing/replayed authorization.
    pub fn mark_certificate_result_unknown_v2(
        &mut self,
        _channel: &AuthenticatedCertificateManagerChannelV2,
        authorization_jti: &str,
        lease_digest_sha256: &str,
        evidence_digest_sha256: &str,
    ) -> Result<()> {
        if !bare_digest(lease_digest_sha256) || !bare_digest(evidence_digest_sha256) {
            return Err(AdministratorError::Contract(
                "evidence_digest_sha256: invalid bare SHA-256 digest".into(),
            ));
        }
        let changed = self.connection.execute(
            "UPDATE certificate_v2_reservations
                SET state = 'result-unknown', unknown_evidence_digest_sha256 = ?
              WHERE authorization_jti = ? AND state = 'executing'
                AND lease_digest_sha256 = ?
                AND unknown_evidence_digest_sha256 IS NULL",
            params![
                evidence_digest_sha256,
                authorization_jti,
                lease_digest_sha256
            ],
        )?;
        (changed == 1)
            .then_some(())
            .ok_or(AdministratorError::Replay)
    }

    /// Records independently verified authority and durable manager evidence.
    ///
    /// # Errors
    ///
    /// Rejects replay or reconciliation that does not reference an unknown operation.
    pub fn complete_certificate_execution_v2(
        &mut self,
        _channel: &AuthenticatedCertificateManagerChannelV2,
        input: &CertificateCompletionInputV2<'_>,
    ) -> Result<CertificateCompletionReceiptV2> {
        if let Some(receipt) = self.prepare_certificate_completion_v2(input)? {
            return Ok(receipt);
        }
        self.finalize_certificate_completion_v2(input)
    }
}

fn bare_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
