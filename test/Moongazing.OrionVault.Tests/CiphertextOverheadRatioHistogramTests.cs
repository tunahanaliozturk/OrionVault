namespace Moongazing.OrionVault.Tests;

using System.Diagnostics.Metrics;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;
using Xunit;

public sealed class CiphertextOverheadRatioHistogramTests
{
    private const string InstrumentName = "orionvault.encryption.ciphertext_overhead_ratio";

    private sealed class FixedKeyProvider : IKeyProvider
    {
        private readonly System.Collections.Generic.Dictionary<short, byte[]> _keys;
        public FixedKeyProvider(short activeKeyId, System.Collections.Generic.Dictionary<short, byte[]> keys)
        {
            ActiveKeyId = activeKeyId;
            _keys = keys;
        }
        public short ActiveKeyId { get; }
        public int KeyCount => _keys.Count;
        public System.ReadOnlyMemory<byte>? TryGetKey(short keyId)
            => _keys.TryGetValue(keyId, out var k) ? k : (System.ReadOnlyMemory<byte>?)null;
    }

    // Filter to THIS diagnostics instance's Meter (reference equality) so a parallel test that
    // encrypts cannot pollute these assertions (the histogram name is process-wide).
    private static MeterListener StartIsolatedListener(OrionVaultDiagnostics diag, System.Collections.Generic.List<double> samples)
    {
        var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (ReferenceEquals(instrument.Meter, diag.Meter) && instrument.Name == InstrumentName)
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<double>((_, val, _, _) =>
        {
            lock (samples) { samples.Add(val); }
        });
        listener.Start();
        return listener;
    }

    private static IEncryptor NewEncryptor(OrionVaultDiagnostics diag)
    {
        var key = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        return OrionVaultEncryptor.Create(new FixedKeyProvider(1, new() { [1] = key }), diag);
    }

    [Fact]
    public void EncryptBytes_records_the_storage_amplification_ratio()
    {
        using var diag = new OrionVaultDiagnostics();
        var samples = new System.Collections.Generic.List<double>();
        using var listener = StartIsolatedListener(diag, samples);

        // 10-byte plaintext -> envelope = 30 fixed overhead (14-byte header + 16-byte tag) + 10
        // = 40 bytes -> amplification ratio 40 / 10 = 4.0.
        NewEncryptor(diag).EncryptBytes(new byte[10]);

        lock (samples) { Assert.Contains(4.0, samples); }
    }

    [Fact]
    public void EncryptBytes_with_empty_plaintext_records_no_ratio()
    {
        using var diag = new OrionVaultDiagnostics();
        var samples = new System.Collections.Generic.List<double>();
        using var listener = StartIsolatedListener(diag, samples);

        NewEncryptor(diag).EncryptBytes(System.Array.Empty<byte>());

        // The ratio is undefined for empty plaintext (the envelope is all fixed overhead), so the
        // encryptor records nothing. Isolation by Meter instance makes this negative assertion safe.
        lock (samples) { Assert.Empty(samples); }
    }
}
