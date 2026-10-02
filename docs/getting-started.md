# Using crowsi-policy-administrator

Convert a permitted policy decision into a bounded execution authorization.

## Before you start

The administrator mediates permission. A separate enforcement point verifies and consumes that permission.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Check trusted evidence and scope.
- Issue an authorization tied to an exact operation.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
