namespace Moongazing.OrionVault.Tests;

using System.Diagnostics.Metrics;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.Exceptions;
using Xunit;

public sealed class AuthTagFailuresCounterTests
{
    private const string InstrumentName = "orion.vault.decryption.auth_tag_failures";

    // A single registered 32-byte key so encrypt/decrypt round-trips.
    private sealed class SingleKeyProvider : IKeyProvider
    {
        private readonly byte[] _key = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        public short ActiveKeyId => 1;
        public int KeyCount => 1;
        public System.ReadOnlyMemory<byte>? TryGetKey(short keyId)
            => keyId == 1 ? _key : (System.ReadOnlyMemory<byte>?)null;
    }

    // Filter to THIS diagnostics instance's Meter (reference equality), not the meter NAME, so a
    // parallel test emitting the same instrument on a different OrionVaultDiagnostics cannot
    // pollute the count. This makes the exact-count assertions reliable under xUnit parallelism.
    private static MeterListener StartIsolatedListener(OrionVaultDiagnostics diag, System.Action<long> add)
    {
        var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (ReferenceEquals(instrument.Meter, diag.Meter) && instrument.Name == InstrumentName)
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, val, _, _) => add(val));
        listener.Start();
        return listener;
    }

    [Fact]
    public void Tampered_ciphertext_increments_auth_tag_failures()
    {
        using var diag = new OrionVaultDiagnostics();
        long total = 0;
        using var listener = StartIsolatedListener(diag, v => System.Threading.Interlocked.Add(ref total, v));

        var encryptor = OrionVaultEncryptor.Create(new SingleKeyProvider(), diag);
        var ciphertext = encryptor.EncryptBytes(new byte[] { 1, 2, 3 });
        // Flip a byte in the tag region so AES-GCM authentication fails.
        ciphertext[ciphertext.Length - 1] ^= 0xff;

        Assert.Throws<OrionVaultDecryptionException>(() => encryptor.DecryptBytes(ciphertext));
        Assert.Equal(1L, System.Threading.Interlocked.Read(ref total));
    }

    [Fact]
    public void A_valid_decrypt_does_not_increment_auth_tag_failures()
    {
        using var diag = new OrionVaultDiagnostics();
        long total = 0;
        using var listener = StartIsolatedListener(diag, v => System.Threading.Interlocked.Add(ref total, v));

        var encryptor = OrionVaultEncryptor.Create(new SingleKeyProvider(), diag);
        var ciphertext = encryptor.EncryptBytes(new byte[] { 1, 2, 3 });
        var plaintext = encryptor.DecryptBytes(ciphertext);

        Assert.Equal(new byte[] { 1, 2, 3 }, plaintext);
        Assert.Equal(0L, System.Threading.Interlocked.Read(ref total));
    }
}
