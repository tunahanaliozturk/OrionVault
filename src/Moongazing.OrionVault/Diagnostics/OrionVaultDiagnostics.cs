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

    public OrionVaultDiagnostics()
    {
        ActivitySource = new ActivitySource(ActivitySourceName, "0.1.0");
        Meter = new Meter(MeterName, "0.1.0");
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
    }

    public void Dispose()
    {
        ActivitySource.Dispose();
        Meter.Dispose();
        GC.SuppressFinalize(this);
    }
}
