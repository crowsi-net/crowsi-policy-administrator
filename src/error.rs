use thiserror::Error;

pub type Result<T> = std::result::Result<T, AdministratorError>;

#[derive(Debug, Error)]
pub enum AdministratorError {
    #[error("control contract rejected: {0}")]
    Contract(String),
    #[error("signature or canonical digest rejected")]
    Signature,
    #[error("artifact key, issuer, audience, or policy is not trusted")]
    Trust,
    #[error("trusted time is unavailable or invalid")]
    Time,
    #[error("trusted clock moved behind the durable watermark")]
    ClockRollback,
    #[error("policy engine denied the operation")]
    PolicyDenied,
    #[error("authorization artifacts are not exactly bound")]
    Binding,
    #[error("grant or command replay was rejected")]
    Replay,
    #[error("isolation epoch changed concurrently")]
    EpochConflict,
    #[error("provider fence changed concurrently")]
    FenceConflict,
    #[error("provider execution result is unknown and requires reconciliation")]
    OutcomeUnknown,
    #[error("authoritative revocation epoch rolled back")]
    Revoked,
    #[error("receipt does not match the reserved command")]
    ReceiptMismatch,
    #[error("administrator state is unavailable")]
    Storage(#[from] rusqlite::Error),
    #[error("administrator ledger identity or schema is invalid")]
    LedgerIntegrity,
    #[error("certificate authorization signer is unavailable")]
    CertificateAuthorizationUnavailable,
}
