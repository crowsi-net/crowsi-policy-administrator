use crate::support;

use crowsi_control_contracts::CanonicalPayloadV1;
use rusqlite::{Connection, params};
use support::{TestLedger, V2Fixture};

#[test]
fn unsigned_command_substitution_in_the_ledger_never_reaches_a_pep() {
    let ledger = TestLedger::new();
    let fixture = V2Fixture::new().expect("fixture");
    {
        let mut administrator = fixture
            .base
            .administrator_on_path_at(ledger.path(), support::FIXED_NOW)
            .expect("administrator");
        administrator
            .reserve_v2(&fixture.reservation())
            .expect("reservation");
    }
    let mut substituted = fixture.command.clone();
    substituted.target_id.push_str("/other");
    substituted.binding.resource = substituted.target_id.clone();
    substituted.signed.digest = substituted.payload_digest();
    let digest = substituted.payload_digest();
    let json = serde_json::to_string(&substituted).expect("JSON");
    Connection::open(ledger.path())
        .expect("raw ledger")
        .execute(
            "UPDATE v2_enforcement_reservations
                SET command_json = ?, command_digest = ?
              WHERE command_jti = ?",
            params![json, digest, fixture.command.jti],
        )
        .expect("simulated storage tampering");
    let mut reopened = fixture
        .base
        .administrator_on_path_at(ledger.path(), support::FIXED_NOW)
        .expect("reopened");
    assert!(reopened.status_v2(&fixture.command.jti).is_err());
    assert!(reopened.begin_execution_v2(&fixture.command.jti).is_err());
}

#[test]
fn terminal_status_requires_the_persisted_signed_receipt() {
    let ledger = TestLedger::new();
    let fixture = V2Fixture::new().expect("fixture");
    {
        let mut administrator = fixture
            .base
            .administrator_on_path_at(ledger.path(), support::FIXED_NOW)
            .expect("administrator");
        administrator
            .reserve_v2(&fixture.reservation())
            .expect("reservation");
    }
    Connection::open(ledger.path())
        .expect("raw ledger")
        .execute(
            "UPDATE v2_enforcement_reservations
                SET state = 'applied', outcome = 'applied',
                    receipt_id = 'receipt.forged',
                    receipt_digest = ?
              WHERE command_jti = ?",
            params![format!("sha256:{}", "9".repeat(64)), fixture.command.jti],
        )
        .expect("simulated state tampering");
    let reopened = fixture
        .base
        .administrator_on_path_at(ledger.path(), support::FIXED_NOW)
        .expect("reopened");
    assert!(reopened.status_v2(&fixture.command.jti).is_err());
}
