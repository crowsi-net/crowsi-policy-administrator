use std::path::Path;

use crowsi_policy_engine::PolicyInput;
use rusqlite::Connection;

use crate::{
    AdministratorError, AdministratorPolicy, Result, SimulationFixedClock, TrustedKeys,
    clock::AdministratorClock, ledger::migrate, ledger_file,
};

pub struct PolicyAdministrator {
    pub(crate) connection: Connection,
    pub(crate) policy: AdministratorPolicy,
    pub(crate) trusted_keys: TrustedKeys,
    pub(crate) clock: AdministratorClock,
}

impl PolicyAdministrator {
    /// Opens an isolated durable execution ledger.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` or the closed migration cannot initialize.
    pub fn open(
        path: &Path,
        policy: AdministratorPolicy,
        trusted_keys: TrustedKeys,
    ) -> Result<Self> {
        let connection = ledger_file::open(path)?;
        Self::from_connection(
            connection,
            policy,
            trusted_keys,
            AdministratorClock::system(),
        )
    }

    /// Opens a file ledger with an explicitly simulation-only fixed clock.
    ///
    /// # Errors
    ///
    /// Returns an error when the clock, `SQLite`, or migration is invalid.
    pub fn open_with_fixed_clock_for_simulation(
        path: &Path,
        policy: AdministratorPolicy,
        trusted_keys: TrustedKeys,
        clock: SimulationFixedClock,
    ) -> Result<Self> {
        Self::from_connection(
            Connection::open(path)?,
            policy,
            trusted_keys,
            AdministratorClock::simulation(clock),
        )
    }

    /// Creates an in-memory ledger with an explicit simulation-only clock.
    ///
    /// # Errors
    ///
    /// Returns an error when the closed migration cannot initialize.
    pub fn in_memory_for_simulation(
        policy: AdministratorPolicy,
        trusted_keys: TrustedKeys,
        clock: SimulationFixedClock,
    ) -> Result<Self> {
        Self::from_connection(
            Connection::open_in_memory()?,
            policy,
            trusted_keys,
            AdministratorClock::simulation(clock),
        )
    }

    fn from_connection(
        connection: Connection,
        policy: AdministratorPolicy,
        trusted_keys: TrustedKeys,
        clock: AdministratorClock,
    ) -> Result<Self> {
        let configured = PolicyInput {
            digest: "",
            max_risk_score: policy.max_risk_score,
            step_up_risk_score: policy.step_up_risk_score,
        }
        .computed_digest();
        if configured != policy.policy_digest {
            return Err(AdministratorError::Trust);
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
        Ok(Self {
            connection,
            policy,
            trusted_keys,
            clock,
        })
    }
}
