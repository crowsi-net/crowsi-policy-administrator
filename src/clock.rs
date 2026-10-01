use time::{
    OffsetDateTime, PrimitiveDateTime, format_description::FormatItem, macros::format_description,
};

use crate::{AdministratorError, Result};

const TIMESTAMP: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

pub struct SimulationFixedClock {
    now: String,
}

impl SimulationFixedClock {
    /// Creates an explicitly non-production fixed clock.
    ///
    /// # Errors
    ///
    /// Rejects values outside the normalized UTC millisecond representation.
    pub fn new(now: &str) -> Result<Self> {
        if !valid_timestamp(now) {
            return Err(AdministratorError::Time);
        }
        Ok(Self {
            now: now.to_owned(),
        })
    }
}

pub(crate) enum AdministratorClock {
    System,
    Simulation(SimulationFixedClock),
}

impl AdministratorClock {
    pub(crate) const fn system() -> Self {
        Self::System
    }

    pub(crate) const fn simulation(clock: SimulationFixedClock) -> Self {
        Self::Simulation(clock)
    }

    pub(crate) fn now(&self) -> String {
        match self {
            Self::System => normalized_now(),
            Self::Simulation(clock) => clock.now.clone(),
        }
    }
}

pub(crate) fn epoch_seconds(value: &str) -> Result<u64> {
    let value = PrimitiveDateTime::parse(value, TIMESTAMP)
        .map_err(|_| AdministratorError::Time)?
        .assume_utc()
        .unix_timestamp();
    u64::try_from(value).map_err(|_| AdministratorError::Time)
}

pub(crate) fn valid_timestamp(value: &str) -> bool {
    value.len() == 24 && PrimitiveDateTime::parse(value, TIMESTAMP).is_ok()
}

fn normalized_now() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond()
    )
}
