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
    internal Counter<long> KeyLookups { get; }
    internal Counter<long> KeyNotFound { get; }
    internal Histogram<double> Duration { get; }
    internal Counter<long> ReEncryptionRowsProcessed { get; }
    internal Histogram<double> ReEncryptionBatchDuration { get; }
    internal Counter<long> RotationRowsRotated { get; }
    internal Counter<long> RotationRowsSkipped { get; }
    internal Counter<long> RotationRowErrors { get; }
    internal Histogram<double> RotationCycleDuration { get; }
    internal Histogram<int> EncryptionPayloadSize { get; }
    internal Histogram<int> DecryptionPayloadSize { get; }

    // v0.2.15 last-cycle snapshot, fed by EncryptionRotationHostedService at the end of
    // every RunCycleAsync. Operators graph the gauges as a "right-now" view of what the
    // last sweep produced, complementing the steady-state counter rates.
    private long lastCycleScanned;
    private long lastCycleRotated;
    private long lastCycleSkipped;
    private long lastCycleErrors;
    private long lastCycleAtUnixSeconds;

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
        KeyLookups = Meter.CreateCounter<long>("orionvault.key_lookups", "{operations}",
            "Number of key lookups performed against the IKeyProvider.");
        KeyNotFound = Meter.CreateCounter<long>("orionvault.key_not_found", "{operations}",
            "Number of times the IKeyProvider returned null for a key id.");
        Duration = Meter.CreateHistogram<double>("orionvault.encryption.duration_ms", "ms",
            "Duration of encrypt/decrypt operations.");
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
    }

    public void Dispose()
    {
        ActivitySource.Dispose();
        Meter.Dispose();
        GC.SuppressFinalize(this);
    }
}
