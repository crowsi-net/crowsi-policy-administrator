use crowsi_control_contracts::{
    CanonicalPayloadV1, EnforcementReceiptV2, IsolationCommandV2, Validate,
};

use crate::{AdministratorError, EnforcementStatusV2, Result};

pub(crate) struct StoredReservationV2 {
    pub command: IsolationCommandV2,
    pub command_digest: String,
    pub reserved_at: String,
    pub expires_at: String,
    pub state: String,
    pub outcome: Option<String>,
    pub receipt_id: Option<String>,
    pub receipt_digest: Option<String>,
}

impl StoredReservationV2 {
    pub(crate) fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        let json = row.get::<_, String>(0)?;
        let command = serde_json::from_str(&json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
        Ok(Self {
            command,
            command_digest: row.get(1)?,
            reserved_at: row.get(2)?,
            expires_at: row.get(3)?,
            state: row.get(4)?,
            outcome: row.get(5)?,
            receipt_id: row.get(6)?,
            receipt_digest: row.get(7)?,
        })
    }

    pub(crate) fn verify(&self, receipt: &EnforcementReceiptV2, now: &str) -> Result<()> {
        self.command
            .validate()
            .map_err(|_| AdministratorError::LedgerIntegrity)?;
        let command = &self.command;
        let exact = command.payload_digest() == self.command_digest
            && receipt.command_jti == command.jti
            && receipt.command_digest == self.command_digest
            && receipt.security_domain == command.security_domain
            && receipt.deployment_id == command.deployment_id
            && receipt.incident_id == command.incident_id
            && receipt.target_id == command.target_id
            && receipt.release_reservation_id == command.release_reservation_id
            && receipt.fence_epoch == command.fence_epoch
            && receipt.binding == command.binding
            && receipt.provider == command.provider
            && receipt.expected_resource_version == command.expected_resource_version
            && self.reserved_at.as_str() <= receipt.applied_at.as_str()
            && receipt.applied_at.as_str() <= now
            && receipt.applied_at.as_str() < self.expires_at.as_str();
        if exact {
            Ok(())
        } else {
            Err(AdministratorError::ReceiptMismatch)
        }
    }

    pub(crate) fn status(&self) -> EnforcementStatusV2 {
        EnforcementStatusV2 {
            command_jti: self.command.jti.clone(),
            security_domain: self.command.security_domain.clone(),
            deployment_id: self.command.deployment_id.clone(),
            target_id: self.command.target_id.clone(),
            fence_epoch: self.command.fence_epoch,
            state: self.state.clone(),
            outcome: self.outcome.clone(),
        }
    }
}
