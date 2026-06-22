# OrionVault Roadmap

OrionVault follows the same release rhythm as the rest of the Orion family: quarterly minor versions, patch releases as needed, and a v1.0 only when the public API surface is stable.

## Current release: 0.3.4 (2026-06-22)

Column-level transparent data encryption at rest for EF Core: AES-256-GCM with a per-row key id, multi-key read / single-key write rotation, a searchable HMAC blind index, an EF Core re-encryption / blind-index re-index runner, AWS KMS and Azure Key Vault providers, a bundled Roslyn analyzer, and OpenTelemetry instrumentation. Multi-targets net8.0 / net9.0 / net10.0.

## Released / recently shipped

The items below were on earlier roadmaps and are now shipped. They are listed here so they are not mistaken for planned work. The [CHANGELOG](CHANGELOG.md) has the per-version detail.

- **Background re-encryption (0.2.0).** `IReEncryptionTarget` + `ReEncryptionHostedService` + `ReEncryptionOptions` drain rows still under retired keys on a schedule, with telemetry and a shutdown drain.
- **AWS KMS provider (0.2.3).** `Moongazing.OrionVault.AwsKms` wraps data keys with a KMS CMK via envelope encryption; only wrapped blobs live in config.
- **Azure Key Vault provider (0.2.4).** `Moongazing.OrionVault.AzureKeyVault`, RSA-OAEP-256 by default with an AES-KW option.
- **KMS integration-test matrix (0.2.5).** LocalStack-backed AWS tests and conditional live-Azure tests.
- **Multi-DbContext support (0.2.6 - 0.2.10).** Named key providers, keyed encryptor / configurator resolution, per-DbContext model-customizer binding, and the one-call `AddOrionVaultBoundDbContext<TDbContext>` helper.
- **Key-rotation primitives (0.2.11 - 0.2.12).** `EncryptionRotator` (one-shot re-encrypt under the active key, with a header-only `NeedsRotation` check) and `EncryptionRotationHostedService<THandle>` over an `IRotationSource<THandle>`.
- **Rotation and crypto telemetry (0.2.13 - 0.2.29).** Rotation cycle counters / gauges, key-resolution and decrypt-duration histograms, payload-size and ciphertext-overhead histograms, auth-tag-failure and legacy-key-used counters, plus the `IDecryptionFailureHandler`, `IKeyRotationObserver`, and `IEncryptionAuditObserver` extensibility hooks.
- **Searchable encryption via a deterministic blind index (0.3.0).** `IBlindIndexProvider` / `HmacBlindIndexProvider` compute a keyed, one-way HMAC-SHA256 digest for equality search while the stored ciphertext stays randomized. Index keys are versioned and rotatable; `ComputeAllVersions` builds the cross-rotation OR-probe and `BlindIndexResult.TryReadVersion` drives the re-index path.
- **Allocation cuts (0.3.2).** Blind-index hot paths encode into stack / pooled buffers (`Matches` is allocation-free); `AesGcmEncryptor.EncryptString` encodes through a pooled buffer. Ciphertext and index output are byte-identical, no wire-format change.
- **Value-object encryption (0.3.3).** A property whose CLR type is not `string` / `byte[]` but carries a value converter to a `string` / `byte[]` provider type (for example a `Tckn` record) is now encrypted by composing the encryption converter on top of the existing one. The on-disk envelope is unchanged.
- **Re-encryption and re-index tooling (0.3.4).** `IEncryptionMaintenance` / `ReencryptionRunner` (EF Core) walk a table in bounded batches and bring every row up to the active key and active blind-index version, reusing `EncryptionRotator` and the blind-index `Compute` / `TryReadVersion` primitives. Idempotent (already-active rows are skipped), resumable (each batch saved before the next is read), cancellable, and reports scanned / re-encrypted / re-indexed / skipped / errors on the existing rotation telemetry. Wired with `UseReencryptionRunner()`.

## Next

Concrete, near-term work that builds on the primitives already shipped.

### 0.4.0 - 2026-Q4

- **Envelope-key caching.** Today the KMS / Key Vault providers unwrap every data key once at startup and hold the plaintext in process memory for the provider's lifetime. Add an opt-in cache layer with a configurable TTL and refresh so long-running hosts can re-fetch wrapped keys (supporting key disable / revocation at the KMS) instead of pinning them for the process lifetime.
- **More KMS providers.** GCP KMS (`Moongazing.OrionVault.GcpKms`) and HashiCorp Vault (`Moongazing.OrionVault.HashiCorp`), each on the same wrap-at-rest, unwrap-at-startup envelope shape as the AWS and Azure providers.

### 0.5.0 - 2027-Q1

- **Per-column key selection.** Let a property choose a key set other than the global `ActiveKeyId` (for example a higher-sensitivity column under a separate KMS-wrapped key) instead of one active write key across the whole model.
- **Deterministic equality-search options for the blind index.** Configurable normalization profiles per index (for example case-sensitive, or culture-aware) so equality search can be tuned per column, documented alongside the confidentiality trade-off that equal values become linkable.

### 0.6.0 - 2027-Q2

- **AOT and trimming posture.** Audit the runtime packages for trim / Native-AOT compatibility, annotate as needed, and add a trimmed smoke-test target so the documented support level is verified rather than assumed. The EF Core model-customizer reflection path is the main thing to validate.

## v1.0 - 2027-Q3

- Public API surface freeze.
- Production-hardened benchmarks (the `bench/` project currently tracked in [benchmarks.md](benchmarks.md)).
- Compliance documentation: KVKK, GDPR, and PCI-DSS mapping.

Dates are targets, not commitments. If something here matters to you, open an issue with the `roadmap` label.
