//! Version-one authorization and recovery contracts share one executable.

#[path = "../support/mod.rs"]
mod support;

#[path = "../authorization.rs"]
mod authorization;
#[path = "../clock_rollback.rs"]
mod clock_rollback;
#[path = "../receipt_time.rs"]
mod receipt_time;
#[path = "../receipts.rs"]
mod receipts;
#[path = "../recovery.rs"]
mod recovery;
#[path = "../trust_boundary.rs"]
mod trust_boundary;
