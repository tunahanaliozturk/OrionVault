# Changelog

All notable changes to OrionVault are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
