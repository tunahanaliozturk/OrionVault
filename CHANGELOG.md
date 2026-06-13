# Changelog

All notable changes to OrionVault are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.26] - 2026-06-13

### Added

#### `orionvault.encryption.failures` counter

`Counter<long>` mirroring the existing `decryption.failures` counter on the encrypt side. Encrypt can fail on key resolution (`key_not_found`) or the AES-GCM operation itself (`crypto_error`). Operators alert on the rate - an encrypt failure is MORE severe than a decrypt failure because it blocks WRITES (data cannot be persisted) rather than reads.

- Tags: `reason` (`key_not_found` / `crypto_error`) and `key_id`.
- The exception still propagates to the caller after the counter increments.
- Recorded in `AesGcmEncryptor.EncryptInternal` catch blocks; the `Duration` finally still fires.

### Tests

1 fact.

### Migration from v0.2.25

Source-compatible.

## [0.2.25] - 2026-06-12

### Added

#### `orionvault.keys.registered_count` ObservableGauge

`ObservableGauge<long>` reports the number of keys registered in the active `IKeyProvider`. Operators compare against their key rotation policy to confirm old keys are eventually retired from configuration (a steadily growing count means retired keys are never being removed).

- `IKeyProvider` gains a `KeyCount` member with a default interface implementation returning `-1` (provider cannot enumerate, e.g. remote KMS) - existing custom providers compile unchanged.
- `StaticKeyProvider` reports its exact dictionary count.
- Snapshot taken once at `IEncryptor` construction; `0` until the encryptor is first resolved.

### Tests

2 facts.

### Migration from v0.2.24

Source-compatible (DIM default keeps custom IKeyProvider implementations compiling).

## [0.2.24] - 2026-06-12

### Added

#### `orionvault.decryption.legacy_key_used` counter

`Counter<long>` increments when a decrypt operation resolves a non-active (legacy) key id. Operators graph the rate to track rotation progress:

- Steadily falling rate = rows are being re-encrypted to the new active key (by the rotation sweep or natural write traffic).
- Flat / rising rate = rotation has stalled OR new ciphertexts are being created under a legacy key (configuration drift).

Tagged with `key_id` (the legacy key id actually used) and `active_key_id` so operators can identify WHICH legacy key has the most outstanding ciphertexts and target re-encryption priority.

### Tests

2 facts.

### Migration from v0.2.23

Source-compatible.

## [0.2.23] - 2026-06-12

### Added

#### `IEncryptionAuditObserver` extensibility

Consumer-supplied observer invoked on EVERY successful encrypt and decrypt. Useful for compliance regimes that require an audit trail of cryptographic operations (key id, byte sizes) without coupling the audit logic to the load-bearing AES path.

- `IEncryptionAuditObserver` interface with `OnEncrypted(keyId, plaintextLen, ciphertextLen)` and `OnDecrypted(keyId, ciphertextLen, plaintextLen)`.
- `NullEncryptionAuditObserver` no-op default.
- New `AesGcmEncryptor` 4-arg ctor wires both `IDecryptionFailureHandler` AND `IEncryptionAuditObserver`; legacy 2-arg and 3-arg ctors preserved.
- `AddOrionVault` now uses explicit DI registration so both hooks wire independently - registering only one no longer silently drops the other (lesson learned from v0.2.20 OrionPatch P1 ActivatorUtilities trap).
- Observer fires AFTER the operation succeeds, BEFORE the result returns. Throwing observer is swallowed so audit-side outage cannot affect the cryptographic path.

### Tests

2 facts.

### Migration from v0.2.22

Source-compatible.

```csharp
services.AddSingleton<IEncryptionAuditObserver, MyAuditObserver>();
```

## [0.2.22] - 2026-06-11

### Added

#### `orionvault.active_key_id` ObservableGauge

`ObservableGauge<long>` reports the currently active write-key id. Operators graph the gauge to verify the configured `IKeyProvider.ActiveKeyId` without scraping logs - a config-drift between deployments or a stale rollout becomes visible on the same dashboard as encryption/rotation telemetry.

- Reports `0` until `SetActiveKeyIdSnapshot` has been called.
- `AddOrionVault(...)` wires the snapshot at construction so the gauge reports the configured value from the moment the host starts emitting metrics.
- Public `OrionVaultDiagnostics.SetActiveKeyIdSnapshot(short)` so consumers can refresh the gauge after a rotation that bumps the active key.

### Tests

1 fact.

### Migration from v0.2.21

Source-compatible.

## [0.2.21] - 2026-06-11

### Added

#### `orionvault.key_resolution.duration_ms` histogram

`Histogram<double>` measuring `IKeyProvider.TryGetKey` wall-clock per call. Operators graph p99 to spot a key provider whose backend (Key Vault, KMS, database-backed `IKeyProvider`) has regressed - the existing `orionvault.encryption.duration_ms` histogram captures the FULL round-trip which mixes key lookup + AES work, hiding backend-side slowdowns inside an otherwise healthy AES path.

- Tagged with `outcome` (`hit` / `miss`).
- Recorded inside `AesGcmEncryptor.LookupKey` around the `_keys.TryGetKey(keyId)` call.

### Tests

1 fact.

### Migration from v0.2.20

Source-compatible.

## [0.2.20] - 2026-06-11

### Added

#### `IKeyRotationObserver` DI-based rotation observer

Consumer-supplied observer invoked after each `EncryptionRotationHostedService<THandle>` cycle. Mirrors the v0.2.14 options-based `ProgressCallback` but registered via DI so it composes naturally with the host's other services (logger factories, tenant scopes).

- `IKeyRotationObserver` in `Moongazing.OrionVault.Abstractions`.
- `NullKeyRotationObserver` no-op default.
- Resolved from the per-cycle service scope; null and Null observers both skip the call.
- Fires AFTER OTel + log + ProgressCallback so observers see the same totals; throwing observer does NOT abort the sweep.
- The legacy `ProgressCallback` still fires; both run when both are configured.

### Tests

2 facts.

### Migration from v0.2.19

Source-compatible.

```csharp
services.AddSingleton<IKeyRotationObserver, MyObserver>();
```

## [0.2.19] - 2026-06-11

### Added

#### `IDecryptionFailureHandler` extensibility

Consumer-supplied observer invoked when an AES-GCM decrypt fails. Useful for routing to an external alerting system (Slack, PagerDuty, SIEM) without baking the routing into the encryptor.

- `IDecryptionFailureHandler` interface in `Moongazing.OrionVault.Abstractions`.
- `NullDecryptionFailureHandler` no-op default.
- AesGcmEncryptor 3-arg ctor wires the optional handler; the 2-arg ctor is preserved for back-compat.
- Handler runs AFTER the failure counter increments and BEFORE the exception propagates; handler exceptions are swallowed so the original failure is never masked.
- Two reasons currently emitted: `tampered`, `key_not_found`.

### Tests

2 facts.

### Migration from v0.2.18

Source-compatible.

```csharp
services.AddSingleton<IDecryptionFailureHandler, MyAlertingHandler>();
```

## [0.2.18] - 2026-06-11

### Added

#### `orionvault.decryption.payload_size_bytes` histogram

`Histogram<int>` mirrors the v0.2.17 encrypt-side histogram for the decrypt path. Operators graph both side-by-side to confirm encrypt/decrypt traffic shape stays balanced.

- Recorded in `AesGcmEncryptor.DecryptInternal` on the success path with `plaintext.Length`.
- Public on `OrionVaultDiagnostics.DecryptionPayloadSize`.

### Tests

1 fact.

### Migration from v0.2.17

Source-compatible.

## [0.2.17] - 2026-06-11

### Added

#### `orionvault.encryption.payload_size_bytes` histogram

`Histogram<int>` exposes the distribution of plaintext payload sizes per encrypt operation. Operators graph p99 to size connection-pool buffers and spot a tenant bulk-import path that drove huge encrypt calls (which the existing duration histogram alone cannot distinguish from "small encrypt + slow AES").

- Recorded in `AesGcmEncryptor.EncryptInternal` per call, value = `plaintext.Length` in bytes.
- Public on `OrionVaultDiagnostics.EncryptionPayloadSize` via the standard internal exposure pattern.
- Complements `orionvault.encryption.duration_ms`: duration is wall-clock, payload_size is byte-shape; the ratio reveals AES throughput.

### Tests

1 fact.

### Migration from v0.2.16

Source-compatible.

## [0.2.16] - 2026-06-11

### Added

#### `orionvault.rotation.last_cycle_at_unix_seconds` ObservableGauge

Unix-seconds timestamp gauge of the last rotation cycle completion. Operators page on `(now() - orionvault_rotation_last_cycle_at_unix_seconds) > N` to detect a stalled rotation host long before the v0.2.15 row counters reveal it.

- Reports 0 until the FIRST cycle completes so "never ran" is distinguishable from "epoch".
- Updated atomically via `Interlocked.Exchange` alongside the v0.2.15 last-cycle counters.
- Pairs with v0.2.15 row-shape gauges: timestamp answers "when did the last sweep run", row counts answer "what did it produce".

### Tests

1 fact.

### Migration from v0.2.15

Source-compatible.

## [0.2.15] - 2026-06-11

### Added

#### `orionvault.rotation.last_cycle.*` ObservableGauges

Four new `ObservableGauge<long>` instruments on `OrionVaultDiagnostics` expose the just-completed rotation cycle as a "right-now" snapshot:

- `orionvault.rotation.last_cycle.scanned`
- `orionvault.rotation.last_cycle.rotated`
- `orionvault.rotation.last_cycle.skipped`
- `orionvault.rotation.last_cycle.errors`

Fed by `EncryptionRotationHostedService.RunCycleAsync` at the end of every cycle via `OrionVaultDiagnostics.SetLastCycleSnapshot`. Operators see the v0.2.13 steady-state counters AND the v0.2.15 gauges side by side: counters answer "what is the rate?", gauges answer "what did the last sweep produce?".

Write side uses `Interlocked.Exchange` so the OTel scraper never reads a torn value.

### Tests

1 fact.

### Migration from v0.2.14

Source-compatible.

## [0.2.14] - 2026-06-11

### Added

#### `EncryptionRotationOptions.ProgressCallback`

Optional per-cycle delegate invoked AFTER OTel emission with the `RotationCycleResult`. Useful for consumer-side dashboards, Slack notifiers, or operator audit logs that want the same totals the v0.2.13 metrics expose.

- `Action<RotationCycleResult>? ProgressCallback` on `EncryptionRotationOptions`.
- Callback exceptions are caught and swallowed: a faulty notifier never aborts the rotation sweep. The sweep is the load-bearing path; the callback is observability.
- Fires AFTER `OrionVaultDiagnostics.RotationCycleDuration.Record` so a callback that reads metrics on the side sees the just-recorded sample.

### Tests

2 new facts.

### Migration from v0.2.13

Source-compatible.

## [0.2.13] - 2026-06-11

### Added

#### Rotation telemetry on `OrionVaultDiagnostics`

Four new instruments wire `EncryptionRotationHostedService<THandle>` (v0.2.12) into OTel so operators can graph rotation progress and convergence without scraping logs.

- `orionvault.rotation.rows_rotated` (`Counter<long>`): rows re-encrypted under the active key id.
- `orionvault.rotation.rows_skipped` (`Counter<long>`): rows where `NeedsRotation` returned false (already on the active key).
- `orionvault.rotation.row_errors` (`Counter<long>`): per-row decrypt / re-encrypt failures that the sweep swallowed and counted.
- `orionvault.rotation.cycle_duration_ms` (`Histogram<double>`): wall-clock per cycle.
- The hosted service resolves `OrionVaultDiagnostics` via `GetService` (optional) - if the consumer has not wired diagnostics the rotation runs unchanged with no emissions.

### Tests

1 new fact.

### Migration from v0.2.12

Source-compatible.

## [0.2.12] - 2026-06-11

### Added

#### `EncryptionRotationHostedService<THandle>` background re-encryption sweep

Builds on the v0.2.11 `EncryptionRotator` primitive. v0.2.11 shipped `Rotate(IEncryptor, byte[])` for one-shot scripts; v0.2.12 ships the hosted-service equivalent.

- `IRotationSource<THandle>` abstracts the storage walk (consumer implements for their table / store).
- `EncryptionRotationHostedService<THandle>.RunCycleAsync` filters via `EncryptionRotator.NeedsRotation`, re-encrypts via `EncryptionRotator.Rotate`, writes through `IRotationSource.UpdateAsync`.
- `EncryptionRotationOptions`: `Interval` (default 6 hours), `MaxRowsPerCycle` (nullable, default unlimited).
- `RotationCycleResult(Scanned, Rotated, Skipped, Errors)` per cycle.
- Per-row failures swallowed + counted so one malformed blob does not abort the sweep.

### Tests

4 new facts.

### Migration from v0.2.11

Source-compatible.

## [0.2.11] - 2026-06-11

### Added

#### `EncryptionRotator` - one-shot key rotation helper

Helper for consumers running a one-shot rotation pass after rolling the `ActiveKeyId` on their `IKeyProvider`. Existing rows still carry the previous-active key id in their AES-GCM header; v0.2.11 ships the primitive that re-encrypts each blob under the new key.

- `EncryptionRotator.NeedsRotation(byte[], activeKeyId)` reads the 2-byte big-endian key id header WITHOUT decrypting so rotation jobs can cheaply skip rows already on the active key.
- `EncryptionRotator.Rotate(IEncryptor, byte[])` decrypts under whatever key id the header carries and re-encrypts under the active key. The encryptor MUST know both keys.
- `EncryptionRotator.RotateString(IEncryptor, byte[])` convenience overload for UTF-8 string columns.
- The rotator does NOT walk EF Core tables itself - consumers feed it a stream of ciphertexts because the query shape depends on the table layout.

### Tests

6 new facts.

### Migration from v0.2.10

Source-compatible.

## [0.2.10] - 2026-06-11

### Added

#### `AddOrionVaultBoundDbContext<TDbContext>` - one-call per-DbContext binding

One-call wiring of the v0.2.7-v0.2.9 per-DbContext binding stack. v0.2.9 required three discrete calls (`UseEntityFrameworkCore<T>(name)`, `AddSingleton(new KeyedOrionVaultBinding<T>(name))`, and `AddDbContext` with `UseApplicationServiceProvider` + `ReplaceService<IModelCustomizer, ...>`) - easy to forget one. v0.2.10 collapses them into a single builder method.

```csharp
services.AddOrionVault(...)
    .AddNamedKeyProvider("primary", primaryProvider)
    .AddOrionVaultBoundDbContext<PrimaryDb>("primary", (sp, opt) => opt.UseSqlServer(connectionString));
```

Under the hood the helper invokes the v0.2.8 keyed registration, the v0.2.9 binding, and `AddDbContext` with the correct `UseApplicationServiceProvider` + `ReplaceService` calls.

### Tests

3 new facts.

### Migration from v0.2.9

Source-compatible.

## [0.2.9] - 2026-06-11

### Added

#### `KeyedOrionVaultModelCustomizer<TDbContext>` - per-DbContext binding wiring

Delivers the EF Core wiring deferred from v0.2.8.

- `KeyedOrionVaultBinding<TDbContext>(providerName)` per-DbContext binding object.
- `KeyedOrionVaultModelCustomizer<TDbContext>` model customizer with parameterless ctor for `ReplaceService<IModelCustomizer, ...>`.
- Resolves the application SP via `CoreOptionsExtension.ApplicationServiceProvider`; reads binding + keyed `IEncryptionConfigurator` from it.
- Throws `InvalidOperationException` with a clear message when the binding is missing or `UseApplicationServiceProvider` was not called.

### Tests

3 new facts.

### Migration from v0.2.8

Source-compatible.

## [0.2.8] - 2026-06-10

### Added

#### Keyed `IEncryptor` / `EncryptedValueConverterFactory` / `IEncryptionConfigurator` per provider name

Builds on the v0.2.7 `IKeyedKeyProviderRegistry` scaffolding. v0.2.8 ships the keyed DI registrations so the host can resolve a separate encryptor per provider name; the v0.3.0 milestone will add the EF Core model-customizer wiring that makes these resolutions kick in automatically per DbContext.

- **`OrionVaultEncryptor.Create(IKeyProvider, OrionVaultDiagnostics) -> IEncryptor`** public factory entry point. Builds an `AesGcmEncryptor` over the supplied key provider without exposing the internal type. Pass the shared `OrionVaultDiagnostics` from DI so the keyed encryptor's telemetry lands on the same activity / counter stream as the default one.
- **`OrionVaultBuilder.UseEntityFrameworkCore<TDbContext>(string providerName)`** registers keyed singletons under `providerName`:
  - `IEncryptor` -> built via `OrionVaultEncryptor.Create` over `IKeyedKeyProviderRegistry.GetProvider(providerName)`.
  - `EncryptedValueConverterFactory` -> bound to the keyed encryptor.
  - `IEncryptionConfigurator` -> bound to the keyed factory.
- Resolve from the host via `sp.GetRequiredKeyedService<IEncryptor>("primary")`.

### Tests

6 new facts cover: keyed `IEncryptor` registered per name (distinct instances), keyed `EncryptedValueConverterFactory` distinct per name, keyed `IEncryptionConfigurator` distinct per name, keyed encryptor encrypts with the named provider's key set (cross-decrypt fails as expected), keyed overload rejects null / empty `providerName`, `OrionVaultEncryptor.Create` round-trips.

### Deferred

- Drop-in EF Core wiring so a DbContext options pipeline can say `opt.UseOrionVault(sp, "primary")` -> v0.3.0 (EF Core `ReplaceService` factory overload constraints).

### Migration from v0.2.7

Source-compatible. The keyed overload is opt-in; existing single-encryptor consumers continue unchanged.

```csharp
services.AddOrionVault(o => { o.UseStaticKeys(...); o.ActiveKeyId = 1; })
    .AddNamedKeyProvider("primary", primaryProvider)
    .AddNamedKeyProvider("audit", auditProvider)
    .UseEntityFrameworkCore<PrimaryDbContext>("primary")
    .UseEntityFrameworkCore<AuditDbContext>("audit");

// resolve per-context:
var primaryEncryptor = sp.GetRequiredKeyedService<IEncryptor>("primary");
```

## [0.2.7] - 2026-06-10

### Added

#### `IKeyedKeyProviderRegistry` - named-provider scaffolding

Foundation for v0.3.0's per-DbContext provider binding. v0.2.7 ships the data structure + DI plumbing so consumers populate the registry today; the v0.3 EF Core overload will resolve named providers without further breaking changes.

- **`IKeyedKeyProviderRegistry`** interface in `Moongazing.OrionVault.Abstractions`: `GetProvider(name)`, `TryGetProvider(name, out)`, `IsRegistered(name)`, `RegisteredNames()`.
- **`KeyedKeyProviderRegistry`** default implementation backed by `ConcurrentDictionary` with a side-list preserving registration order. Idempotent `Register(name, provider)` - first call wins, subsequent calls return `false`.
- **`OrionVaultBuilder.AddNamedKeyProvider(name, IKeyProvider)`** and **`AddNamedKeyProvider(name, Func<IServiceProvider, IKeyProvider>)`** DI extensions. Factory overload runs against the resolved `IServiceProvider` so named providers can take construction dependencies from DI.
- The existing default `IKeyProvider` registration continues to work unchanged. The registry is opt-in.

### Tests

12 new facts; 41 total in core suite.

### Deferred

- Per-DbContext provider binding (`UseEntityFrameworkCore<TDbContext>("primary")`) -> v0.3.0.

### Migration from v0.2.6

Source-compatible.

## [0.2.6] - 2026-06-10

### Added

#### Multi-DbContext support

The pre-v0.2.6 docstring warned that calling `UseEntityFrameworkCore<TDbContext>()` twice was unsafe; in practice the registered services already used `TryAddSingleton` so the second call would short-circuit instead of overwriting, but the contract was undocumented. v0.2.6 confirms the contract and adds the ergonomics consumers were writing by hand.

- **`UseEntityFrameworkCore<TDbContext>()` is now explicitly documented as idempotent** across multiple DbContext types. All registered DbContexts share ONE `IEncryptor` + key set (the common case: primary + audit DBs encrypted with the same KMS-wrapped data keys). Distinct key providers per DbContext stay a v0.3 milestone.
- **`AddOrionVaultDbContext<TDbContext>(this IServiceCollection, configureContext, contextLifetime?, optionsLifetime?)`** combined-registration shortcut: registers the OrionVault EF Core wiring AND wires `UseOrionVault` INSIDE an `AddDbContext<TDbContext>` call, so single-line wiring fits in the consumer's `Program.cs`. Lifetime parameters mirror the EF Core defaults (scoped). The wrapper invokes the consumer callback FIRST so provider selection (`UseSqlServer` / `UseNpgsql` / etc.) is applied before OrionVault attaches on top.

### Tests

4 new `MultiDbContextTests` facts: two DbContext types sharing one encryptor (end-to-end SQLite round-trip), stored ciphertext differs across two DbContext writes due to per-call AES-GCM nonce, `AddOrionVaultDbContext` shortcut wires `UseOrionVault` correctly, null-callback rejection. 15 facts total in the EF Core integration suite.

### Migration from v0.2.5

Source-compatible. Existing single-DbContext wiring keeps working. For two DbContexts sharing one encryptor:

```csharp
services.AddOrionVault(o =>
    {
        o.UseStaticKeys(k => k.Add(1, "BASE64-KEY"));
        o.ActiveKeyId = 1;
    })
    .UseEntityFrameworkCore<PrimaryDbContext>()
    .UseEntityFrameworkCore<AuditDbContext>()
    .Services
    .AddDbContext<PrimaryDbContext>((sp, o) => o.UseSqlServer(...).UseOrionVault(sp))
    .AddDbContext<AuditDbContext>((sp, o) => o.UseSqlServer(...).UseOrionVault(sp));
```

Or with the single-line shortcut:

```csharp
services.AddOrionVault(o => { ... }).Services
    .AddOrionVaultDbContext<PrimaryDbContext>((sp, o) => o.UseSqlServer(...))
    .AddOrionVaultDbContext<AuditDbContext>((sp, o) => o.UseSqlServer(...));
```

## [0.2.5] - 2026-06-10

### Added

#### Integration test matrix for `AwsKms` and `AzureKeyVault` providers

Lands the deferral chain that goes back to v0.2.3 / v0.2.4 (mocked unit tests shipped, integration tests staged). End-to-end coverage now exists for both envelope-encryption providers.

- **`Moongazing.OrionVault.AwsKms.IntegrationTests`** (NEW PROJECT) - spins up LocalStack (KMS emulator) via Testcontainers, generates a CMK with `CreateKeyAsync`, wraps two 32-byte plaintext keys, and exercises the production `AwsKmsKeyProvider.CreateAsync` path against the real AWS API surface. 3 facts: two-key unwrap + active id resolvable, 8-key parallel decrypt (verifies the `Task.WhenAll` fan-out works against a live broker without deadlocks), 16-byte plaintext rejected as != 32 bytes by the provider's post-unwrap validation. Tagged `[Trait("Category", "Integration")]` so the on-CI matrix can opt them in / out.
- **`Moongazing.OrionVault.AzureKeyVault.IntegrationTests`** (NEW PROJECT) - live Azure Key Vault provider tests via `DefaultAzureCredential`. Key Vault has no widely-available local emulator (Azurite covers Storage but not Key Vault), so these are CONDITIONAL on the consumer setting `ORIONVAULT_AZURE_KEYVAULT_URI` + `ORIONVAULT_AZURE_KEYVAULT_KEY_NAME`. Skipped via the minimal in-test `SkippableFact` polyfill when the env vars are absent. 2 facts: two-key unwrap against a live RSA wrap key, 16-byte plaintext rejected. Inline `LiveUnwrapAdapter` wraps `CryptographyClient` to satisfy the `IKeyVaultUnwrapClient` contract (the production `CryptographyClientUnwrapAdapter` is internal to the provider package on purpose).

### Tests

Existing 17 unit facts (8 AwsKms + 9 AzureKeyVault) continue to pass; 5 new integration facts (3 LocalStack-backed + 2 live-Azure conditional) bring the OrionVault provider suites to 22 facts when integration matrix is on.

### Deferred

- Multi-DbContext support -> v0.2.6 (unchanged target)

### Migration from v0.2.4

Source-compatible. Integration test projects are not published as NuGet packages and do not affect consumers.

## [0.2.4] - 2026-06-10

### Added

#### `Moongazing.OrionVault.AzureKeyVault` (NEW PACKAGE) - Azure Key Vault key provider

Wraps OrionVault's symmetric data keys with an Azure Key Vault KEK (RSA-OAEP-256 by default, AES-KW for HSM-backed AES keys). The KEK never leaves Azure Key Vault; OrionVault config / source control holds only the wrapped (KEK-ciphertext) blobs. Unwrap runs once at startup against Azure Key Vault, then plaintext data keys stay in process memory for the provider's lifetime.

- **`AzureKeyVaultKeyProvider`** implements `IKeyProvider`. Multi-key read, single-key write rotation (same shape as `AwsKmsKeyProvider`): `ActiveKeyId` is used for new encryptions; previously-active ids stay resolvable so existing rows decrypt during a rotation rollout.
- **`AzureKeyVaultKeyProviderOptions`** binds `KeyName` (vault key name or full key identifier), optional `KeyVersion` (defaults to current), `WrapAlgorithm` (default `RsaOaep256`), `ActiveKeyId`, and a `WrappedKeys` map of (`short keyId`, `base64 ciphertext`). At least one entry is required.
- **`AzureKeyVaultKeyProvider.CreateAsync(IKeyVaultUnwrapClient, options, ct)`** async factory unwraps each configured ciphertext blob in parallel and returns a ready-to-use provider. Local input validation: null/whitespace ciphertext, non-base64, zero-byte decoded ciphertext, blank `KeyName`, missing active id, wrong-length plaintext all surface as `OrionVaultConfigurationException` at startup.
- **`IKeyVaultUnwrapClient`** narrow abstraction so the provider can be unit-tested without spinning up a real `CryptographyClient`; the production DI adapter forwards to `CryptographyClient.UnwrapKeyAsync(algorithm, ...)`.
- **`AddOrionVaultAzureKeyVault(this IServiceCollection, configure)`** DI helper registers the provider as singleton. Consumers register the `KeyClient` themselves (e.g., `services.AddSingleton(new KeyClient(new Uri(...), new DefaultAzureCredential()))`) so the credentials story stays in the consumer's hands.

### Deferred

- **LocalStack integration tests for AWS KMS provider** -> v0.2.5 (kept on the roadmap; bundled with Azure Key Vault integration tests when CI gains the broker matrix)
- **Multi-DbContext support** -> v0.2.6 (bumped one minor to make room for the integration-test slot)

### Migration from v0.2.3

Source-compatible. Add-on is opt-in:

```csharp
services.AddSingleton(new KeyClient(
    new Uri("https://my-vault.vault.azure.net/"),
    new DefaultAzureCredential()));

services.AddOrionVaultAzureKeyVault(o =>
{
    o.KeyName = "orionvault-kek";
    o.ActiveKeyId = 1;
    o.WrappedKeys[1] = "BASE64-AZURE-WRAPPED-DATA-KEY-1";
});

services.AddOrionVault(...);
```

## [0.2.3] - 2026-06-09

### Added

#### `Moongazing.OrionVault.AwsKms` (NEW PACKAGE) - AWS KMS key provider

Wraps OrionVault's symmetric data keys with an AWS KMS customer master key (CMK) via envelope encryption. The CMK never leaves AWS; OrionVault config / source control holds only the wrapped (KMS-ciphertext) blobs. Decryption runs once at startup against AWS KMS, then plaintext data keys stay in process memory for the provider's lifetime.

- **`AwsKmsKeyProvider`** implements `IKeyProvider`. Supports the standard OrionVault rotation pattern: `ActiveKeyId` is used for new encryptions; previously-active ids stay resolvable so existing rows decrypt during a rotation rollout.
- **`AwsKmsKeyProviderOptions`** binds `ActiveKeyId` + a `WrappedKeys` map of (`short keyId`, `base64 ciphertext`). At least one entry is required.
- **`AwsKmsKeyProvider.CreateAsync(IAmazonKeyManagementService, options, ct)`** async factory decrypts each configured ciphertext blob in parallel and returns a ready-to-use provider. Throws `OrionVaultConfigurationException` for empty options, invalid base64, missing-active-id, or wrong-length keys (must be exactly 32 bytes).
- **`AddOrionVaultAwsKms(this IServiceCollection, configure)`** DI helper registers the provider as a singleton. Consumers register the KMS client themselves via `services.AddAWSService<IAmazonKeyManagementService>()` so the credentials story stays in the consumer's hands.

### Deferred

- **LocalStack integration tests** for the KMS provider -> v0.2.4 (alongside Azure Key Vault).
- Azure Key Vault provider -> v0.2.4 (unchanged)
- Multi-DbContext support -> v0.2.5 (unchanged)

### Migration from v0.2.2

Source-compatible. Add-on is opt-in:

```csharp
services.AddAWSService<IAmazonKeyManagementService>();
services.AddOrionVaultAwsKms(o =>
{
    o.ActiveKeyId = 1;
    o.WrappedKeys[1] = "BASE64-KMS-CIPHERTEXT-FOR-KEY-1";
});
services.AddOrionVault(...);
```

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

[Unreleased]: https://github.com/tunahanaliozturk/OrionVault/compare/v0.2.24...HEAD
[0.2.24]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.2.24
[0.2.23]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.2.23
[0.2.22]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.2.22
[0.2.21]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.2.21
[0.2.20]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.2.20
[0.2.19]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.2.19
[0.2.18]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.2.18
[0.2.17]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.2.17
[0.2.16]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.2.16
[0.2.1]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.2.1
[0.2.0]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.2.0
[0.1.2]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.1.2
[0.1.1]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.1.1
[0.1.0]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.1.0
