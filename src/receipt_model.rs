use crowsi_control_contracts::EnforcementReceiptV1;

use crate::{
    AdministratorError, EnforcementStatus, Result,
    reserve::{action_name, channel_name},
};

pub(crate) struct StoredReservation {
    pub grant_jti: String,
    pub resource: String,
    pub audience: String,
    pub action: String,
    pub purpose: String,
    pub channel: String,
    pub isolation_epoch: u64,
    pub state: String,
    pub receipt_id: Option<String>,
    pub receipt_digest: Option<String>,
    pub reserved_at: String,
    pub command_expires_at: String,
}

impl StoredReservation {
    pub(crate) fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        let epoch = row.get::<_, i64>(6)?;
        Ok(Self {
            grant_jti: row.get(0)?,
            resource: row.get(1)?,
            audience: row.get(2)?,
            action: row.get(3)?,
            purpose: row.get(4)?,
            channel: row.get(5)?,
            isolation_epoch: u64::try_from(epoch)
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(6, epoch))?,
            state: row.get(7)?,
            receipt_id: row.get(8)?,
            receipt_digest: row.get(9)?,
            reserved_at: row.get(10)?,
            command_expires_at: row.get(11)?,
        })
    }

    pub(crate) fn verify(&self, receipt: &EnforcementReceiptV1, now: &str) -> Result<()> {
        let binding = &receipt.binding;
        let matches = self.grant_jti == receipt.enforcement_grant_jti
            && self.resource == binding.resource
            && self.audience == binding.audience
            && self.action == action_name(binding.action)
            && self.purpose == binding.purpose
            && self.channel == channel_name(binding.channel)
            && receipt.provider == self.audience
            && self.reserved_at.as_str() <= receipt.applied_at.as_str()
            && receipt.applied_at.as_str() <= now
            && receipt.applied_at.as_str() < self.command_expires_at.as_str();
        if matches {
            Ok(())
        } else {
            Err(AdministratorError::ReceiptMismatch)
        }
    }

    pub(crate) fn status(&self, command_jti: &str) -> EnforcementStatus {
        EnforcementStatus {
            resource: self.resource.clone(),
            isolation_epoch: self.isolation_epoch,
            command_jti: command_jti.to_owned(),
            state: self.state.clone(),
            outcome: Some(self.state.clone()),
        }
    }
}
