# Crowsi Policy Administrator

`crowsi-policy-administrator` is the local Policy Administrator (PA) boundary
between a deterministic Crowsi policy decision and a provider-specific Policy
Enforcement Point (PEP).

It does not change a firewall, cloud account, host, or network. It verifies a
closed authorization chain and signed policy-information snapshot, reads its
own clock, re-runs the pure Policy Engine, consumes the exact grant, release
reservation, and command once in a SQLite transaction, advances resource
fences and subject epochs, and records a role-scoped signed PEP receipt.

## Trust boundary

The caller supplies signed artifacts, but no raw `EvaluationInput` or clock:

- an identity context issued for the configured issuer and audience;
- a short-lived intent, decision, one-use grant, and command with one exact
  subject/device/workload/profile/action/resource/purpose/channel binding;
- a short-lived signed `PolicyInformationSnapshotV1` covering posture,
  incident, management authority, authoritative revocation epoch, risk,
  policy, and the exact signed coverage digest;
- a separate one-use `RecoveryAuthorizationV1` for restore;
- Ed25519 verifiers configured with one artifact role and exact scope each.

Production `open` uses the PA-owned system UTC clock. Tests and simulations
must opt into `SimulationFixedClock` through the explicitly named in-memory
or file-ledger constructors. Reserve and receipt operations advance a durable
SQLite clock watermark and reject a current time behind it, including after a
restart. The PA checks canonical digests, signatures, validity windows,
bindings, policy result, replay state, and epochs before returning a
reservation. The PA contains no command signer and accepts only an externally
signed V2 command whose public key is registered for the exact command role
and scope. The coordinator must consume the release reservation atomically
before its credential broker asks an HSM, TPM, or equivalent boundary to sign.

A V2 reservation is not evidence of execution or an indefinitely valid
capability. `begin_execution_v2` transitions it once and returns a
`PepExecutionLeaseV2`. The PEP must revalidate the command, require the latest
fence, and apply `expected_resource_version` as one provider-native
compare-and-swap. An ambiguous provider result is persisted as
`result-unknown`; later commands for that resource remain blocked until the
exact signed V2 receipt reconciles it.

An `applied` receipt is only a signed claim that a trusted PEP reported success.
Independent sensors and the incident coordinator must verify the resulting
network state before the system may report containment.

## Certificate lifecycle boundary

The same PA owns the policy side of the closed certificate V2 flow without
becoming a CA or certificate manager. It keeps `issue`, `renew`, `revoke`,
`certificate-status`, `operation-status`, and `reconcile-unknown` as separate
actions. Every action carries policy-authorization ancestry; mutations and
reconciliation additionally require separately verified phishing-resistant
operator evidence and requester/approver separation. Status operations require
operator evidence to be absent.

Certificate authorization release is two phase. The signed lease first enters
`released-pending-accept` without advancing its fence or lifecycle epoch. The
manager durably records the exact operation claim and signs it with the
dedicated `certificate-manager-handoff-receipt` key. Only after PA verifies
that evidence under current trust, revocation, time, and immutable row
bindings does one transaction promote the fence/epoch and record the ACK.
Expired, unaccepted claims become `not-accepted` and are discarded; exact ACK
replay after response loss is idempotent.

Completion also uses two independent proofs: the CA's outcome evidence and the
manager's durable-commit evidence. The PA stores an exact inbox record before
acknowledging delivery. Commit event time, later evidence-issuance time, the
short transport lifetime, and the signed maximum 24-hour submission-recovery
deadline are distinct. `still-unknown`, a changed proof, expired recovery, or
current trust/revocation failure never releases the original lock.

Certificate roles use distinct material and scopes for authorization,
authority result, manager handoff, and manager commit. The PA verifies
canonical P-256 P1363 low-S receipts for the latter three roles and rejects
key ID, version, SPKI, purpose, algorithm, scope, or signature substitution.
The owner-only SQLite schema is version 7; older or partially migrated
certificate tables fail closed and require an explicit offline migration.

## Minimal use

```rust
let mut keys = TrustedKeys::default();
keys.insert_ed25519(
    "identity.control.1",
    ArtifactRole::Identity,
    KeyScope::Identity { issuer, audience },
    identity_public_key,
)?;
// Register distinct keys and scopes for every other artifact role.
let mut pa = PolicyAdministrator::open(
    Path::new("/var/lib/crowsi-pa/crowsi-pa.sqlite3"),
    policy,
    keys,
)?;

let reservation = pa.reserve_v2(&signed_hsm_command_input)?;
let status = pa.execute_v2(&reservation.command_jti, &mut provider_pep)?;
```

Production `open` requires an absolute canonical path, a dedicated parent
directory with mode `0700`, and a regular ledger with mode `0600` owned by the
same OS identity as that directory. SQLite opens with `NOFOLLOW`; startup also
attests the complete table/index DDL before accepting the ledger. Simulation
constructors remain explicitly separate and do not make those deployment
claims.

`EnforcementPointV2` is a narrow port, not a provider implementation. The
production port accepts only the control-contracts
`PepExecutionLeaseV2` wire and returns only a signed
`EnforcementReceiptV2`; v1 or provider-local substitutes are rejected. A PEP
must durably consume every fence greater than its latest fence before checking
or changing provider state, retain it after a known resource-version
rejection, and reject every older or equal fence. The in-memory conformance
test demonstrates these semantics without changing a real provider. See the
tests for complete signed chains, concurrent writers, restart, rollback,
replay, and unknown-result cases.

The versioned PEP conformance release artifacts are under
`fixtures/conformance/v1/`. The checked lease is generated by the real
`reserve_v2` then `begin_execution_v2` path and is compared as exact pretty
JSON, including field order and trailing newline. Its companion command-trust
manifest contains only the Ed25519 public verifier, role, audience scope,
security boundary, and accepted schema URIs. It is explicitly
`conformance-only`; never add the deterministic test private key to that
manifest or promote its verifier into production trust.

## Deliberate exclusions

- no provider SDK, shell command, process execution, or network client;
- no automatic restoration or fallback permit;
- no environment-variable or plaintext key loading;
- no claim of complete visibility, successful isolation, or compromise
  detection without independent coverage evidence;
- no multi-node consensus. One PA ledger is authoritative for its resource
  partition; federation must preserve single-writer epochs or add consensus.

Production signing keys belong in the Crowsi credential broker backed by an OS
key store, TPM, HSM, or equivalent hardware boundary. This crate exposes no
private-key loading or command-issuance API. Deterministic software authorities
exist only inside the integration-test support tree.

Security depends on uncompromised role-scoped verifiers and signer, an accurate
host clock, an intact ledger, canonical provider resource identifiers, and a
PEP that performs expiry, fence, and resource-version checks. The command
signer must be reachable only from the coordinator's verified atomic release
consumer; possession of that signer is authority to mint commands. Database
rollback or cloning is not detected by this single-node crate; anchor epochs
externally or use a consensus-backed authority where rollback resistance spans
hosts.

An erroneous forward host-clock jump is deliberately fail-closed: it advances
the watermark and later corrected time remains rejected. Investigate the clock
incident and recover from an authenticated ledger backup or a separately
anchored watermark; do not edit the watermark in place.
