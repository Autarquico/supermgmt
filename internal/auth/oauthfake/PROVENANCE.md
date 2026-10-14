# oauthfake provenance

The fake models only what ADR-0033 needs from an authorization server. Each
behaviour is recorded from a specification, not observed from a product. The
RFC texts were **not re-read** while writing the fake; the section numbers are
from the author's knowledge and should be re-checked before the table is cited
as evidence.

| Behaviour | Source |
|---|---|
| JWKS document `{"keys": [...]}` with `kty`, `use`, `alg`, `kid`, `n`, `e` | RFC 7517 §4, §5; RFC 7518 §6.3 |
| Access token as a JWT with header `typ: at+jwt` and claims `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id`, `scope` | RFC 9068 §2.1, §2.2 |
| `scope` as a space-delimited string | RFC 9068 §2.2.3; RFC 6749 §3.3 |
| RS256 signature (RSASSA-PKCS1-v1_5 with SHA-256) | RFC 7518 §3.3 |
| `alg: none` unsecured JWT, empty signature | RFC 7519 §6 |
| HS256 keyed with the public key (algorithm confusion) | RFC 8725 §2.1, §3.1 |
| Key rotation: a new `kid` appears in the JWKS, old keys stay until retired | RFC 7517 §4.5 (`kid`), OpenID Connect Core §10.1.1 |

Not modelled: authorization or token endpoints, dynamic client registration,
ES/PS/EdDSA signing, `cnf` (DPoP). A real authorization server, including RFC
8707 `resource` at authorization and token exchange, stays a deferred manual
check (PLAN §9, Q11).
