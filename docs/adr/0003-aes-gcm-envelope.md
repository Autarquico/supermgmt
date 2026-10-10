# ADR-0003: AES-256-GCM envelope encryption

- Status: Accepted (implementation in M2)
- Spec: §10

## Decision

Secrets use envelope encryption with AES-256-GCM from the Go standard library: a per-secret random data key (DEK) encrypts the payload; a master key (KEK) identified by `kek_id` wraps the DEK. Nonces are random 96-bit values. Associated data uses length-prefixed domain-separation labels exactly as specified in §10, and the export format is the `SMKEY1` format of §10.

## Consequences

No third-party cryptography is introduced. Master-key rotation re-wraps DEKs only, in one SQLite transaction. The random-nonce bound of AES-GCM (2^32 encryptions per key) is far above the expected volume because every secret update uses a fresh DEK.
