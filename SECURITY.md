# Security policy

## Security invariants within the configured single-ledger boundary

- A reservation is returned only after closed-contract, scoped-signature,
  trusted-time, policy, replay, binding, and epoch checks pass.
- A grant and command JTI can be reserved only once.
- A V2 release identifier, digest, reservation, command digest, and fence can
  each be reserved only once.
- A recovery JTI can be reserved only once and only for an exact restore.
- A resource isolation epoch advances by exactly one in the same immediate
  SQLite transaction as the reservation.
- A V2 resource fence is scoped by security domain, deployment, provider, and
  target and advances by exactly one in the reservation transaction.
- The highest accepted issuer-and-subject revocation epoch cannot decrease
  without rolling back or replacing the ledger.
- Reserve and receipt reject a PA clock value below the durable global
  watermark, including after process restart.
- Restoration is evaluated by the Policy Engine and requires
  signed `RecoveryAuthorized` state, hardware-bound step-up assurance, and a
  separately scoped recovery-authority signature.
- A receipt cannot change the original action binding and cannot be replaced
  after recording.
- An execution lease is released once; an uncertain provider result locks the
  resource until exact signed-receipt reconciliation.
- PEP receipts are not independent verification evidence.
- A released certificate authorization does not advance its fence or lifecycle
  epoch until the manager's separately signed durable handoff is verified.
- A manager handoff ACK is replayable only for byte-equivalent evidence; an
  unaccepted expired claim is abandoned without a CA call.
- Certificate completion requires both exact CA outcome evidence and distinct
  manager durable-commit evidence, recorded in the PA inbox before ACK.
- Certificate policy authorization and operator approval are independent
  ancestries. Status has no operator evidence; privileged actions require it.
- Authorization, authority receipt, manager handoff, and manager commit keys
  cannot reuse key ID or SPKI material.

## Deployment requirements

Production open rejects non-canonical paths, symlinks, non-private parent/file
permissions, a parent not owned by the process effective UID, a file not owned
by that same UID, and unexpected table/index DDL. Still protect the database
with full-disk encryption, authenticated backups, and a dedicated
application-specific OS identity. The PA has no command-signing or private-key
loading API. Permit only externally signed commands from an attested
hardware-backed credential broker, and rotate verifier allowlists with an
overlap and revocation procedure.

Use a dedicated out-of-band management lifeline that the isolation policy
cannot remove. Exercise quarantine, credential revocation, independent
verification, staged restoration, and backup recovery. Until those controls
are both configured and freshly proven, publish the asset as `unmanaged`,
`partial`, or `unknown`, never `controlled`.

SQLite protects one local ledger from concurrent writers; it does not create
distributed consensus. Do not mount the same database over an unsafe shared
filesystem. Federated nodes need explicit resource ownership, conflict
handling, signed audit exchange, and an epoch authority.

The certificate tables use an exact version-7 schema with foreign-key and DDL
attestation. Do not copy selected rows, repair missing indexes in place, or
allow SQLite to infer a migration. Stop the service, retain an authenticated
backup, run a separately reviewed migration that validates every binding and
orphan, then atomically replace the owner-only database.

Treat the host clock as a security input. The ledger uses WAL journaling,
`synchronous=FULL`, full-fsync settings where supported, and a transactional
clock watermark. A database rollback can roll back the watermark too, so
protect and externally anchor the ledger where that threat is in scope. A
forward clock fault intentionally blocks later operations until investigated.

A PEP must use a trusted execution-time clock, the reservation command digest
and expiry, its durable latest fence, and provider-native compare-and-swap
against `expected_resource_version`. It must consume a greater fence before
the compare-and-swap and retain that fence after a known version rejection.
Reservation and execution are separate events; a state change between them
must cause the PEP to abort without reopening the consumed fence.

Role separation limits one verifier compromise but does not make an authority
infallible. A compromised policy-information key can fabricate posture,
incident, management, risk, and revocation claims. A compromised provider
receipt key can fabricate executor claims. Independent sensors remain
necessary; no receipt alone establishes containment or compromise detection.

## Reporting

Treat signature bypass, replay, epoch rollback, receipt substitution, policy
result mismatch, privilege expansion, or an incorrect `controlled` state as
security defects. Preserve the signed artifacts and ledger copy, revoke the
affected identity/grants, isolate through the verified rescue path, and follow
the Crowsi incident-response runbook.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
