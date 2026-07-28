namespace Moongazing.OrionVault.Tests;

using System.Diagnostics.Metrics;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.Exceptions;
using Xunit;

public sealed class DecryptionDurationHistogramTests
{
    private const string InstrumentName = "orion.vault.decryption.duration_ms";

    private sealed class SingleKeyProvider : IKeyProvider
    {
        private readonly byte[] _key = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        public short ActiveKeyId => 1;
        public int KeyCount => 1;
        public System.ReadOnlyMemory<byte>? TryGetKey(short keyId)
            => keyId == 1 ? _key : (System.ReadOnlyMemory<byte>?)null;
    }

    // Filter to THIS diagnostics instance's Meter (reference equality) so a parallel test emitting
    // the same instrument on a different OrionVaultDiagnostics cannot pollute the count.
    private static MeterListener StartIsolatedListener(OrionVaultDiagnostics diag, System.Action<double> add)
    {
        var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (ReferenceEquals(instrument.Meter, diag.Meter) && instrument.Name == InstrumentName)
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<double>((_, val, _, _) => add(val));
        listener.Start();
        return listener;
    }

    [Fact]
    public void A_successful_decrypt_records_a_duration_sample()
    {
        using var diag = new OrionVaultDiagnostics();
        var count = 0;
        using var listener = StartIsolatedListener(diag, _ => System.Threading.Interlocked.Increment(ref count));

        var encryptor = OrionVaultEncryptor.Create(new SingleKeyProvider(), diag);
        var ciphertext = encryptor.EncryptBytes(new byte[] { 1, 2, 3 });
        var plaintext = encryptor.DecryptBytes(ciphertext);

        Assert.Equal(new byte[] { 1, 2, 3 }, plaintext);
        Assert.True(System.Threading.Volatile.Read(ref count) >= 1);
    }

    [Fact]
    public void A_failed_decrypt_also_records_a_duration_sample()
    {
        using var diag = new OrionVaultDiagnostics();
        var count = 0;
        using var listener = StartIsolatedListener(diag, _ => System.Threading.Interlocked.Increment(ref count));

        var encryptor = OrionVaultEncryptor.Create(new SingleKeyProvider(), diag);
        var ciphertext = encryptor.EncryptBytes(new byte[] { 1, 2, 3 });
        ciphertext[ciphertext.Length - 1] ^= 0xff; // tamper the tag so decryption fails

        Assert.Throws<OrionVaultDecryptionException>(() => encryptor.DecryptBytes(ciphertext));
        // The finally records duration on the failure path too.
        Assert.True(System.Threading.Volatile.Read(ref count) >= 1);
    }
}
