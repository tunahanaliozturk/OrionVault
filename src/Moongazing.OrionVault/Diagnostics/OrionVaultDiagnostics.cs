namespace Moongazing.OrionVault.Diagnostics;

using System.Diagnostics;
using System.Diagnostics.Metrics;

public sealed class OrionVaultDiagnostics : IDisposable
{
    public const string MeterName = "Moongazing.OrionVault";
    public const string ActivitySourceName = "Moongazing.OrionVault";

    public ActivitySource ActivitySource { get; }
    public Meter Meter { get; }

    internal Counter<long> Encryptions { get; }
    internal Counter<long> Decryptions { get; }
    internal Counter<long> DecryptionFailures { get; }
    internal Counter<long> AuthTagFailures { get; }
    internal Counter<long> KeyLookups { get; }
    internal Counter<long> KeyNotFound { get; }
    internal Histogram<double> Duration { get; }
    internal Histogram<double> DecryptionDuration { get; }
    internal Counter<long> ReEncryptionRowsProcessed { get; }
    internal Histogram<double> ReEncryptionBatchDuration { get; }
    internal Counter<long> RotationRowsRotated { get; }
    internal Counter<long> RotationRowsSkipped { get; }
    internal Counter<long> RotationRowErrors { get; }
    internal Histogram<double> RotationCycleDuration { get; }
    internal Histogram<int> EncryptionPayloadSize { get; }
    internal Histogram<int> DecryptionPayloadSize { get; }
    internal Histogram<double> CiphertextOverheadRatio { get; }
    internal Counter<long> LegacyKeyUsedOnDecrypt { get; }
    internal Counter<long> EncryptionFailures { get; }
    internal Histogram<double> KeyResolutionDuration { get; }

    // v0.2.15 last-cycle snapshot, fed by EncryptionRotationHostedService at the end of
    // every RunCycleAsync. Operators graph the gauges as a "right-now" view of what the
    // last sweep produced, complementing the steady-state counter rates.
    private long lastCycleScanned;
    private long lastCycleRotated;
    private long lastCycleSkipped;
    private long lastCycleErrors;
    private long lastCycleAtUnixSeconds;
    // v0.2.25 registered key count snapshot. Set once at IEncryptor construction
    // from IKeyProvider.KeyCount. -1 = provider cannot enumerate; 0 = no snapshot yet.
    private long registeredKeyCount;

    /// <summary>
    /// v0.2.25: snapshot the active provider's registered key count. Valid values are
    /// <c>-1</c> (provider cannot enumerate) or <c>&gt;= 0</c>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="count"/> is below -1.</exception>
    public void SetRegisteredKeyCountSnapshot(int count)
    {
        // v0.2.25 fix (coderabbit minor): enforce the documented value domain so an
        // out-of-range count cannot leak an invalid telemetry state.
        if (count < -1)
        {
            throw new ArgumentOutOfRangeException(nameof(count), count, "Key count must be -1 (not enumerable) or >= 0.");
        }
        Interlocked.Exchange(ref registeredKeyCount, count);
    }
    // v0.2.22 active key id snapshot, fed by SetActiveKeyIdSnapshot at startup (and on
    // every key provider refresh if the host wires it). 0 until first set; operators
    // graph the gauge as 'right-now which key is the active write key' so a stale
    // rollout / config drift is visible without scraping logs.
    private long activeKeyId;

    /// <summary>
    /// v0.2.22 active-key snapshot setter. Call once at startup and after every
    /// IKeyProvider refresh so the ObservableGauge reports the current write key.
    /// </summary>
    public void SetActiveKeyIdSnapshot(short value)
        => Interlocked.Exchange(ref activeKeyId, value);

    internal void SetLastCycleSnapshot(int scanned, int rotated, int skipped, int errors)
    {
        Interlocked.Exchange(ref lastCycleScanned, scanned);
        Interlocked.Exchange(ref lastCycleRotated, rotated);
        Interlocked.Exchange(ref lastCycleSkipped, skipped);
        Interlocked.Exchange(ref lastCycleErrors, errors);
        Interlocked.Exchange(ref lastCycleAtUnixSeconds, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    public OrionVaultDiagnostics()
    {
        ActivitySource = new ActivitySource(ActivitySourceName, "0.2.0");
        Meter = new Meter(MeterName, "0.2.0");
        Encryptions = Meter.CreateCounter<long>("orionvault.encryptions", "{operations}",
            "Number of encryption operations performed.");
        Decryptions = Meter.CreateCounter<long>("orionvault.decryptions", "{operations}",
            "Number of decryption operations performed.");
        DecryptionFailures = Meter.CreateCounter<long>("orionvault.decryption.failures", "{operations}",
            "Number of failed decryptions, tagged by reason.");
        // v0.2.27 dedicated AES-GCM authentication-tag failure counter. Increments only when the
        // crypto failure is specifically an AuthenticationTagMismatchException - the precise
        // signal that a ciphertext was tampered with, encrypted under a different key, or
        // corrupted. The broader decryption.failures{reason=tampered} counter still fires for
        // every crypto failure; this one isolates the tamper signal so operators can alert on it
        // without catching unrelated CryptographicExceptions.
        AuthTagFailures = Meter.CreateCounter<long>("orionvault.decryption.auth_tag_failures", "{operations}",
            "Number of decryptions that failed AES-GCM authentication-tag verification (tamper / wrong key / corruption).");
        // v0.2.26 encrypt-side failure counter, mirroring the decryption.failures
        // counter. Encrypt can fail on key resolution (key_not_found) or the AES
        // operation itself (crypto_error). Operators alert on the rate; an encrypt
        // failure is more severe than a decrypt failure because it blocks WRITES
        // (data cannot be persisted) rather than reads.
        EncryptionFailures = Meter.CreateCounter<long>("orionvault.encryption.failures", "{operations}",
            "Number of failed encryptions, tagged by reason.");
        KeyLookups = Meter.CreateCounter<long>("orionvault.key_lookups", "{operations}",
            "Number of key lookups performed against the IKeyProvider.");
        KeyNotFound = Meter.CreateCounter<long>("orionvault.key_not_found", "{operations}",
            "Number of times the IKeyProvider returned null for a key id.");
        Duration = Meter.CreateHistogram<double>("orionvault.encryption.duration_ms", "ms",
            "Duration of encrypt operations (decrypt latency moved to orionvault.decryption.duration_ms in v0.2.28).");
        // v0.2.28 dedicated decrypt-latency histogram. The v0.2.x encryption.duration_ms above
        // only ever received encrypt samples; decrypt latency was unmeasured. This mirrors it on
        // the decrypt side so operators can graph p99 decrypt latency (key resolution + AES-GCM
        // verify + plaintext copy) independently and spot a slow-decrypt regression.
        DecryptionDuration = Meter.CreateHistogram<double>("orionvault.decryption.duration_ms", "ms",
            "Duration of decrypt operations (success and failure).");
        ReEncryptionRowsProcessed = Meter.CreateCounter<long>("orionvault.reencryption.rows_processed", "{rows}",
            "Number of rows re-encrypted by the background re-encryption service.");
        ReEncryptionBatchDuration = Meter.CreateHistogram<double>("orionvault.reencryption.batch_duration_ms", "ms",
            "Duration of one re-encryption batch.");
        // v0.2.13: per-cycle counters for the EncryptionRotationHostedService<THandle>
        // sweep. Operators graph rate(orionvault_rotation_rows_rotated_total[5m]) and
        // p99(orionvault_rotation_cycle_duration_ms) to see how quickly the active key
        // rollout is converging across an estate without scraping log lines.
        RotationRowsRotated = Meter.CreateCounter<long>("orionvault.rotation.rows_rotated", "{rows}",
            "Rows the EncryptionRotationHostedService re-encrypted under the active key.");
        RotationRowsSkipped = Meter.CreateCounter<long>("orionvault.rotation.rows_skipped", "{rows}",
            "Rows already on the active key id (NeedsRotation returned false).");
        RotationRowErrors = Meter.CreateCounter<long>("orionvault.rotation.row_errors", "{rows}",
            "Rows that threw during decrypt or re-encrypt (cycle continues; rows are not aborted).");
        RotationCycleDuration = Meter.CreateHistogram<double>("orionvault.rotation.cycle_duration_ms", "ms",
            "Wall-clock duration of one rotation cycle.");
        // v0.2.17 distribution of plaintext payload size in bytes per encrypt call.
        // Operators graph p99 to size connection-pool buffers and spot a tenant
        // bulk-import path that drove huge encrypt calls (which the duration histogram
        // alone cannot distinguish from "small encrypt + slow AES").
        EncryptionPayloadSize = Meter.CreateHistogram<int>(
            "orionvault.encryption.payload_size_bytes", "By",
            "Plaintext size per encrypt operation in bytes.");
        // v0.2.18 mirror of EncryptionPayloadSize for the decrypt path. Operators graph
        // both side-by-side to confirm encrypt/decrypt traffic shape stays balanced
        // (large imbalance suggests asymmetric load patterns - e.g. write-heavy ingest).
        DecryptionPayloadSize = Meter.CreateHistogram<int>(
            "orionvault.decryption.payload_size_bytes", "By",
            "Plaintext size per decrypt operation in bytes.");
        // v0.2.29 storage-amplification ratio: ciphertext envelope bytes divided by plaintext
        // bytes per encrypt. AES-GCM adds a FIXED header (key id + nonce) plus the auth tag, so
        // the absolute byte overhead is constant - but the RATIO is not: tiny payloads amplify
        // heavily (a 4-byte column can more than double once the fixed overhead is added) while
        // large payloads approach 1.0. That non-linearity is why this is a distinct signal and
        // not derivable from the v0.2.17 payload_size_bytes p99 alone. Operators graph p99 to
        // budget at-rest storage for an encrypted-column workload and to spot a schema dominated
        // by many small encrypted columns whose fixed overhead dominates total storage. Empty
        // plaintext is not recorded (the ratio is undefined).
        CiphertextOverheadRatio = Meter.CreateHistogram<double>(
            "orionvault.encryption.ciphertext_overhead_ratio", "1",
            "Ciphertext envelope bytes divided by plaintext bytes per encrypt (storage amplification).");
        // v0.2.25 registered-key-count gauge. Snapshot set once at IEncryptor
        // construction from IKeyProvider.KeyCount; -1 = provider cannot enumerate
        // (remote KMS), 0 = no snapshot yet. Operators compare against their key
        // rotation policy to confirm old keys are eventually retired from config.
        _ = Meter.CreateObservableGauge<long>("orionvault.keys.registered_count",
            () => Interlocked.Read(ref registeredKeyCount),
            "{keys}", "Number of keys registered in the active IKeyProvider (-1 when not enumerable).");
        // v0.2.24 legacy-key-used counter. Increments when a decrypt operation
        // resolves an OLDER key id than the currently configured ActiveKeyId.
        // Operators graph the RATE to see rotation progress: a steadily falling rate
        // means rows are being re-encrypted to the new active key (by the rotation
        // sweep or natural write traffic); a flat rate means rotation has stalled.
        // Tagged with the actual key_id used so operators can identify WHICH legacy
        // key has the most outstanding ciphertexts.
        LegacyKeyUsedOnDecrypt = Meter.CreateCounter<long>(
            "orionvault.decryption.legacy_key_used", "{operations}",
            "Decrypt operations that resolved a non-active (legacy) key id.");
        // v0.2.21 distribution of IKeyProvider.TryGetKey wall-clock per call. Operators
        // graph p99 to spot a key provider whose backend (Key Vault, KMS, database) has
        // regressed - the encryption.duration histogram captures the full round-trip
        // which mixes key lookup + AES work, hiding backend slowdowns inside an
        // otherwise healthy AES path. Tagged by outcome (hit/miss).
        KeyResolutionDuration = Meter.CreateHistogram<double>(
            "orionvault.key_resolution.duration_ms", "ms",
            "IKeyProvider.TryGetKey wall-clock per call.");
        // v0.2.15 last-cycle ObservableGauges. The callback returns the value snapshotted
        // by the most recent RunCycleAsync; the OTel scraper reads it synchronously.
        _ = Meter.CreateObservableGauge<long>("orionvault.rotation.last_cycle.scanned", () => Interlocked.Read(ref lastCycleScanned),
            "{rows}", "Rows the last rotation cycle scanned.");
        _ = Meter.CreateObservableGauge<long>("orionvault.rotation.last_cycle.rotated", () => Interlocked.Read(ref lastCycleRotated),
            "{rows}", "Rows the last rotation cycle rotated.");
        _ = Meter.CreateObservableGauge<long>("orionvault.rotation.last_cycle.skipped", () => Interlocked.Read(ref lastCycleSkipped),
            "{rows}", "Rows the last rotation cycle skipped (already on active key).");
        _ = Meter.CreateObservableGauge<long>("orionvault.rotation.last_cycle.errors", () => Interlocked.Read(ref lastCycleErrors),
            "{rows}", "Per-row errors in the last rotation cycle.");
        // v0.2.16 timestamp gauge in Unix seconds. Operators page on
        // `(now() - orionvault_rotation_last_cycle_at_unix_seconds) > N` to detect a
        // stalled rotation host long before the row counters reveal it. Reports 0 until
        // the FIRST cycle completes so 'never ran' is distinguishable from 'epoch'.
        _ = Meter.CreateObservableGauge<long>("orionvault.rotation.last_cycle_at_unix_seconds", () => Interlocked.Read(ref lastCycleAtUnixSeconds),
            "s", "Unix seconds timestamp of the last rotation cycle completion (0 if no cycle has run yet).");
        // v0.2.22 active-key gauge. Reports 0 until SetActiveKeyIdSnapshot has been
        // called; consumers wire it inside their AddOrionVault registration so the
        // metric reflects the configured IKeyProvider.ActiveKeyId.
        _ = Meter.CreateObservableGauge<long>("orionvault.active_key_id",
            () => Interlocked.Read(ref activeKeyId),
            "{key_id}", "Currently active write-key id (0 if SetActiveKeyIdSnapshot has not been called).");
    }

    public void Dispose()
    {
        ActivitySource.Dispose();
        Meter.Dispose();
        GC.SuppressFinalize(this);
    }
}
