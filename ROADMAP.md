# OrionVault Roadmap

OrionVault follows the same release rhythm as the rest of the Orion family: quarterly minor versions, patch releases as needed, and a v1.0 only when the public API surface is stable.

## v0.1.0 - 2026-Q2 (current)

- Column encryption for `string` and `byte[]` via AES-256-GCM
- Multi-key read, single-key write key rotation
- `[Encrypted]` attribute and `IsEncrypted()` fluent API
- Roslyn analyzer (OV0001, OV0002, OV0003)
- Testing package with deterministic `TestKeyProvider`
- Telemetry: 1 ActivitySource, 5 counters, 1 histogram

## v0.2.0 - 2026-06-03 *(shipped)*

- Background re-encryption hosted service (`IReEncryptionTarget` + `ReEncryptionHostedService` + `ReEncryptionOptions`). Drains rows still encrypted under retired keys on a configurable schedule with telemetry and shutdown drain.
- New telemetry instruments: `orionvault.reencryption.rows_processed` counter and `orionvault.reencryption.batch_duration_ms` histogram on the existing `Moongazing.OrionVault` Meter.

### Deferred from v0.2.0 to follow-up patches

The original v0.2 milestone listed four items. Three move to focused follow-up patches:

- **AWS KMS provider** (`Moongazing.OrionVault.AwsKms`) -> v0.2.3 (shipped 2026-06-09)
- **Azure Key Vault provider** (`Moongazing.OrionVault.AzureKeyVault`) -> v0.2.4 (shipped 2026-06-10: RSA-OAEP-256 default + AES-KW option, mocked-vault unit tests). LocalStack + Azure integration tests bundled into v0.2.5.
- **First-class multi-DbContext support** -> v0.2.6 (bumped one minor to make room for the integration-test slot at v0.2.5)

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
