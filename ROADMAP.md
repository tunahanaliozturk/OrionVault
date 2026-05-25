# OrionVault Roadmap

OrionVault follows the same release rhythm as the rest of the Orion family: quarterly minor versions, patch releases as needed, and a v1.0 only when the public API surface is stable.

## v0.1.0 - 2026-Q2 (current)

- Column encryption for `string` and `byte[]` via AES-256-GCM
- Multi-key read, single-key write key rotation
- `[Encrypted]` attribute and `IsEncrypted()` fluent API
- Roslyn analyzer (OV0001, OV0002, OV0003)
- Testing package with deterministic `TestKeyProvider`
- Telemetry: 1 ActivitySource, 5 counters, 1 histogram

## v0.2 - 2026-Q4

- AWS KMS provider (`Moongazing.OrionVault.AwsKms`)
- Azure Key Vault provider (`Moongazing.OrionVault.AzureKeyVault`)
- Background re-encryption hosted service for draining retired keys
- First-class multi-DbContext support

## v0.3 - 2027-Q1

- Numeric, DateTime, decimal type support
- Searchable encrypted columns via HMAC index property convention
- Migration helper for converting existing plaintext columns

## v0.4 - 2027-Q1/Q2

- Windows DPAPI provider (`Moongazing.OrionVault.Dpapi`)
- HashiCorp Vault provider (`Moongazing.OrionVault.HashiCorp`)
- Per-tenant key partitioning

## v1.0 - 2027-Q2

- Public API surface freeze
- Production-hardened benchmarks
- Compliance documentation (KVKK, GDPR, PCI-DSS mapping)
