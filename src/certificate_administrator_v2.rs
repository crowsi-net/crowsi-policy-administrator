use std::path::Path;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::Connection;

use crate::{
    CertificateAdministratorPolicyV2, Result, SimulationFixedClock, TrustedKeys,
    certificate_ledger_binding_v2, certificate_normalizer_v2::SimulationExactTargetNormalizerV2,
    certificate_policy_config_v2::validate_policy_config, clock::AdministratorClock,
    ledger::migrate, ledger_file,
};

pub struct CertificatePolicyAdministratorV2 {
    pub(crate) connection: Connection,
    pub(crate) policy: CertificateAdministratorPolicyV2,
    pub(crate) trusted_keys: TrustedKeys,
    pub(crate) clock: AdministratorClock,
    pub(crate) target_normalizer: Option<Box<dyn crate::TargetResourceNormalizerVerifierPortV2>>,
}

impl CertificatePolicyAdministratorV2 {
    /// Opens a private durable certificate authorization ledger.
    ///
    /// # Errors
    ///
    /// Rejects an insecure path, invalid policy, or incompatible ledger.
    pub fn open(
        path: &Path,
        policy: CertificateAdministratorPolicyV2,
        trusted_keys: TrustedKeys,
    ) -> Result<Self> {
        Self::from_connection(
            ledger_file::open(path)?,
            policy,
            trusted_keys,
            AdministratorClock::system(),
            None,
        )
    }

    /// Creates an in-memory certificate PA for deterministic simulation.
    ///
    /// # Errors
    ///
    /// Rejects invalid policy or an incompatible migration.
    pub fn in_memory_for_simulation(
        policy: CertificateAdministratorPolicyV2,
        trusted_keys: TrustedKeys,
        clock: SimulationFixedClock,
    ) -> Result<Self> {
        Self::from_connection(
            Connection::open_in_memory()?,
            policy,
            trusted_keys,
            AdministratorClock::simulation(clock),
            Some(Box::new(SimulationExactTargetNormalizerV2)),
        )
    }

    /// Opens a private file ledger with a deterministic simulation clock.
    ///
    /// This constructor exists for crash/restart conformance tests and does
    /// not weaken the production constructor's unavailable provider boundary.
    ///
    /// # Errors
    ///
    /// Rejects an insecure path, invalid policy, or incompatible ledger.
    pub fn open_with_fixed_clock_for_simulation(
        path: &Path,
        policy: CertificateAdministratorPolicyV2,
        trusted_keys: TrustedKeys,
        clock: SimulationFixedClock,
    ) -> Result<Self> {
        Self::from_connection(
            ledger_file::open(path)?,
            policy,
            trusted_keys,
            AdministratorClock::simulation(clock),
            Some(Box::new(SimulationExactTargetNormalizerV2)),
        )
    }

    fn from_connection(
        mut connection: Connection,
        policy: CertificateAdministratorPolicyV2,
        trusted_keys: TrustedKeys,
        clock: AdministratorClock,
        target_normalizer: Option<Box<dyn crate::TargetResourceNormalizerVerifierPortV2>>,
    ) -> Result<Self> {
        validate_policy_config(&policy)?;
        let signer_key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&policy.authorization_signer_public_key_base64)
            .map_err(|_| crate::AdministratorError::Trust)?
            .try_into()
            .map_err(|_| crate::AdministratorError::Trust)?;
        if trusted_keys.contains_ed25519_key(&signer_key) {
            return Err(crate::AdministratorError::Trust);
        }
        let completion_keys_valid = policy.authorization_verifier_key_id
            != policy.authority_receipt_key_id
            && policy.authorization_verifier_key_id != policy.manager_commit_key_id
            && policy.authorization_verifier_key_id != policy.manager_handoff_key_id
            && policy.authority_receipt_key_id != policy.manager_commit_key_id
            && policy.authority_receipt_key_id != policy.manager_handoff_key_id
            && policy.manager_commit_key_id != policy.manager_handoff_key_id
            && trusted_keys.matches_p256_binding(
                &policy.authority_receipt_key_id,
                &policy.authority_receipt_key_version,
                &policy.authority_receipt_public_key_spki_sha256,
                &policy.authority_receipt_key_purpose,
                crate::ArtifactRole::CertificateAuthorityOutcomeEvidence,
                &crate::KeyScope::AuthorityOutcome {
                    issuer: policy.authority_outcome_issuer.clone(),
                    audience: policy.authority_outcome_audience.clone(),
                    authority_id: policy.certificate_authority_id.clone(),
                    security_domain: policy.security_domain.clone(),
                    deployment_id: policy.deployment_id.clone(),
                },
            )
            && trusted_keys.matches_p256_binding(
                &policy.manager_commit_key_id,
                &policy.manager_commit_key_version,
                &policy.manager_commit_public_key_spki_sha256,
                &policy.manager_commit_key_purpose,
                crate::ArtifactRole::CertificateManagerCommitEvidence,
                &crate::KeyScope::ManagerCommit {
                    issuer: policy.manager_commit_issuer.clone(),
                    audience: policy.manager_commit_audience.clone(),
                    workload: policy.manager_commit_workload.clone(),
                    security_domain: policy.security_domain.clone(),
                    deployment_id: policy.deployment_id.clone(),
                },
            )
            && trusted_keys.matches_p256_binding(
                &policy.manager_handoff_key_id,
                &policy.manager_handoff_key_version,
                &policy.manager_handoff_public_key_spki_sha256,
                &policy.manager_handoff_key_purpose,
                crate::ArtifactRole::CertificateManagerHandoffEvidence,
                &crate::KeyScope::ManagerHandoff {
                    issuer: policy.manager_handoff_issuer.clone(),
                    audience: policy.manager_handoff_audience.clone(),
                    workload: policy.manager_handoff_workload.clone(),
                    security_domain: policy.security_domain.clone(),
                    deployment_id: policy.deployment_id.clone(),
                },
            );
        if !completion_keys_valid {
            return Err(crate::AdministratorError::Trust);
        }
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA busy_timeout = 3000;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA fullfsync = ON;
             PRAGMA checkpoint_fullfsync = ON;
             PRAGMA wal_autocheckpoint = 1000;",
        )?;
        migrate(&connection)?;
        certificate_ledger_binding_v2::pin(&mut connection, &policy)?;
        Ok(Self {
            connection,
            policy,
            trusted_keys,
            clock,
            target_normalizer,
        })
    }
}
