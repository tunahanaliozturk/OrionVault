# Changelog

All notable changes to OrionVault are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.2] - 2026-06-09

### Added

#### `EncryptionAssertions.IsNotEncrypted` (encryptor-backed)

The proper version of the helper that was dropped from v0.2.1 because the length-only heuristic produced false positives on long plaintext columns. Now takes the consumer's registered `IEncryptor` and attempts a real decrypt; success means the bytes ARE encrypted under a registered key and the assertion fires.

- **`IsNotEncrypted(byte[], IEncryptor)`** - short-circuits on bytes shorter than `CipherFormat.MinimumCiphertextLength` (definitively plaintext), otherwise attempts `encryptor.DecryptBytes` and asserts it fails. AES-GCM tag mismatch, unknown key id, malformed header - all surface as "not encrypted".
- Pairs with the v0.2.0 background re-encryption service: regression tests can now confirm that columns are truly plaintext after `[Encrypted]` is removed, not just length-different.

### Deferred

- AWS KMS provider -> v0.2.3 (was v0.2.2; renamed because the testing helper takes that slot)
- Azure Key Vault provider -> v0.2.4 (was v0.2.3)
- First-class multi-DbContext support -> v0.2.5 (was v0.2.4)

`ROADMAP.md` reflects the new sequence.

### Migration from v0.2.1

Source-compatible. `IsNotEncrypted` is a new additive overload; existing assertion code is unchanged.

## [0.2.1] - 2026-06-04

### Added

#### `EncryptionAssertions` testing helpers

Two additive assertions on the existing `Moongazing.OrionVault.Testing.EncryptionAssertions` surface for at-rest validation in consumer integration tests:

- **`IsEncryptedWithActiveKey(byte[], IKeyProvider)`** - asserts the column is encrypted under the supplied provider's `ActiveKeyId`. Useful for re-encryption rollout tests where you want to confirm rows have migrated to the current key after the v0.2.0 background re-encryption service has run.
- **`DoesNotContainPlaintext(byte[], string expected)`** - decodes the column under STRICT UTF-8 (`UTF8Encoding(throwOnInvalidBytes: true)`) and asserts the literal plaintext does not appear. The "I just inserted 'secret123'; prove it is not stored verbatim" assertion when the consumer reads back the raw column via raw SQL. Strict decoding matters: the default `Encoding.UTF8` silently replaces invalid bytes with U+FFFD, which would let stray ciphertext bytes decode to noisy text and risk false positives.

xmldoc on every public method documents the failure shape, intended consumer scenario, and the relationship to the existing AES-GCM / `CipherFormat` layout.

### Deferred

Original v0.2 milestone retargeting from the v0.2.0 CHANGELOG holds. The AWS KMS provider was originally targeted at v0.2.1 here. It is retargeted to **v0.2.2** because credible delivery requires LocalStack-based integration testing + an `Amazon.Extensions.Configuration.SystemsManager`-shaped option binder, both of which are larger than this patch can credibly contain. v0.2.1 ships the highest-value testing-side helpers instead so the v0.2.0 background re-encryption service has matching assertion ergonomics. Other targets unchanged:

- **AWS KMS provider** -> v0.2.2 (retargeted from v0.2.1)
- **Azure Key Vault provider** -> v0.2.3 (retargeted from v0.2.2)
- **First-class multi-DbContext support** -> v0.2.4 (retargeted from v0.2.3)
- **`IsNotEncrypted(byte[])`** helper - deferred from this PR because a length-based heuristic gives false positives on long plaintext columns. v0.2.x will ship the encryptor-backed variant `IsNotEncrypted(byte[], IEncryptor, IKeyProvider)` that attempts a decrypt and only passes when the decrypt fails for every registered key.

`ROADMAP.md` reflects the new sequence.

### Migration from v0.2.0

Source-compatible. The new assertions are additive on the existing static `EncryptionAssertions` class; no DI changes are required.

## [0.2.0] - 2026-06-03

### Added

#### Background re-encryption service

- **`IReEncryptionTarget`** abstraction. A single-method contract (`Task<int> ReEncryptBatchAsync(CancellationToken)`) that consumer code implements over its own DbContext / data source. The implementation queries for rows still encrypted under retired keys, decrypts with the old key, re-encrypts with the active key via the registered `IEncryptor`, persists, and returns the count of rows processed.
- **`ReEncryptionHostedService`** - generic-host `BackgroundService` that wraps the target with schedule, telemetry, and shutdown drain. Default schedule is 6 hours; first tick fires after the schedule so a freshly-started host does not immediately churn the DB. Per-batch exceptions are logged and the service survives to retry on the next tick.
- **`ReEncryptionOptions`** with `Schedule` (default 6h), `Enabled` (default `true`, hot-toggled via `IOptionsMonitor`), and `DrainTimeout` (default 30s) that caps how long shutdown waits for the in-flight batch.
- DI: `services.AddOrionVault(...).UseReEncryptionService<MyTarget>(opts => opts.Schedule = TimeSpan.FromHours(1))`. Consumers who do not register the service see no behaviour change.

#### Telemetry

- New counter: `orionvault.reencryption.rows_processed` ({rows}) - successful re-encrypt count per batch.
- New histogram: `orionvault.reencryption.batch_duration_ms` (ms) - wall-clock duration of one batch including consumer query + decrypt + encrypt + persist.
- New activity: `OrionVault.ReEncryptionBatch` (started on the existing `Moongazing.OrionVault` `ActivitySource`, version bumped to `0.2.0`).
- `OrionVaultDiagnostics.ActivitySource` and `Meter` version strings track the package version (0.2.0).

### Deferred from v0.2.0

The original v0.2.0 milestone listed four items. Three are de-scoped to keep this minor focused and reviewable:

- **`Moongazing.OrionVault.AwsKms`** provider package -> v0.2.1.
- **`Moongazing.OrionVault.AzureKeyVault`** provider package -> v0.2.2.
- **First-class multi-DbContext support** -> v0.2.3. Today consumers compose multiple OrionVault scopes manually per DbContext; the v0.2.3 work adds named registrations and per-scope `IKeyProvider` resolution.

`docs/ROADMAP.md` reflects the new targets.

### Migration from v0.1.2

Source-compatible. The background service is opt-in via `.UseReEncryptionService<T>(...)`; consumers that do not register it see no runtime change. Existing telemetry instruments retain their names and units; the package-version bump on the `ActivitySource` and `Meter` is non-breaking.

## [0.1.2] - 2026-05-26

### Changed

- BREAKING: package IDs renamed from `Moongazing.OrionVault[.X]` to `OrionVault[.X]` to match the rest of the Orion family (OrionGuard, OrionAudit, OrionLock, OrionKey, OrionPatch all ship without the `Moongazing.` prefix). Existing 0.1.0 / 0.1.1 packages under the old IDs remain available on NuGet for backward compatibility but will not receive further updates; new development should reference the unprefixed packages.

### Migration

Replace `<PackageReference Include="Moongazing.OrionVault" Version="0.1.1" />` with `<PackageReference Include="OrionVault" Version="0.1.2" />` (same for `.EntityFrameworkCore` and `.Testing`). No code changes required; namespaces and public API are unchanged.

## [0.1.1] - 2026-05-26

### Changed

- Logo now ships with a cream (#F7F1E3) background instead of transparent. Improves contrast against dark-mode README rendering and NuGet package card backgrounds. No functional change.

## [0.1.0] - 2026-05-25

### Added

- Initial release. Column-level transparent data encryption at rest for EF Core.
- `IEncryptor`, `IKeyProvider`, `IEncryptionConfigurator` core abstractions.
- AES-256-GCM cipher with `[keyId(2) | nonce(12) | tag(16) | ciphertext(N)]` on-disk layout.
- In-config `StaticKeyProvider`. Multi-key read, single-key write key rotation.
- `[Encrypted]` attribute and `IsEncrypted()` fluent API for marking properties.
- Automatic value-converter wiring via `IModelCustomizer` decoration.
- `Moongazing.OrionVault.Testing` package: `TestKeyProvider`, `PlaintextEncryptor`, `EncryptionAssertions`, `AddOrionVaultForTesting()` extension.
- Bundled Roslyn analyzer: OV0001 (type), OV0002 (Where comparison), OV0003 (OrderBy/GroupBy).
- Telemetry via `OrionVault.Diagnostics`: `ActivitySource`, 5 counters, 1 histogram.
- Multi-target net8.0 / net9.0 / net10.0.

### Known limitations

- Single OrionVault-bound DbContext per host. First-class multi-DbContext support is on the v0.2 roadmap.
- Manual re-encryption only (SQL `UPDATE` round-trip through value converter). Background drain hosted service is on the v0.2 roadmap.
- Only `string` and `byte[]` CLR types are supported. Numeric/DateTime/decimal/JSON types are on the v0.3 roadmap.
- No cloud KMS providers yet (AWS, Azure, GCP, HashiCorp, DPAPI). All planned for v0.2 / v0.4 roadmap.

[Unreleased]: https://github.com/tunahanaliozturk/OrionVault/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.2.1
[0.2.0]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.2.0
[0.1.2]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.1.2
[0.1.1]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.1.1
[0.1.0]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.1.0
