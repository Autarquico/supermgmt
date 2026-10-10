# ADR-0004: OpenSSH release signatures

- Status: Accepted (implementation in M2)
- Spec: §3.2, §36

## Decision

Release integrity uses OpenSSH signatures (`ssh-keygen -Y sign/verify`, namespace `supermgmt-release`, principal `release@supermgmt`) over `checksums.txt`, signed channel files and `install.sh`. Sigstore/SLSA provenance is published in addition for auditors but is not required by the bootstrap.

## Consequences

No extra verifier needs to be installed on supported hosts (OpenSSH ≥ 8.1); hosts without `-Y verify` fail closed (exit 4). The trust root of `curl | bash` is the repository's `main` branch plus the release key, as stated in §3.2; the release private key is human-custodied in a protected environment and is never available to CI on pull requests.
