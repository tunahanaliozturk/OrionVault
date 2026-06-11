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
    }

    public void Dispose()
    {
        ActivitySource.Dispose();
        Meter.Dispose();
        GC.SuppressFinalize(this);
    }
}
