# crowsi-policy-administrator

Convert a permitted policy decision into a bounded execution authorization.

## What you can do

- Check trusted evidence and scope.
- Issue an authorization tied to an exact operation.

## Current scope

The administrator mediates permission. A separate enforcement point verifies and consumes that permission.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Examples and interface details

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

## Documentation and source

[Interface reference](docs/interface-reference.md)

[Usage guide](docs/getting-started.md)

[Schemas](schemas) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
