# Changelog

All notable changes to OrionVault are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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

[Unreleased]: https://github.com/tunahanaliozturk/OrionVault/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.1.1
[0.1.0]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.1.0
