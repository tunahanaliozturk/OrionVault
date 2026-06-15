namespace Moongazing.OrionVault.Tests;

using System.Diagnostics.Metrics;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;
using Xunit;

public sealed class LegacyKeyUsedCounterTests
{
    private const string InstrumentName = "orionvault.decryption.legacy_key_used";

    // A provider with an explicit active key id and a fixed key table.
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

    // Filter to THIS diagnostics instance's Meter (reference equality), not the meter NAME, so a
    // parallel test that decrypts a legacy-key ciphertext cannot pollute these exact-count
    // assertions. (Decryption.legacy_key_used is a process-wide instrument name.)
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
    public void Decrypt_with_active_key_does_NOT_increment_legacy_counter()
    {
        using var diag = new OrionVaultDiagnostics();
        long count = 0;
        using var listener = StartIsolatedListener(diag, v => System.Threading.Interlocked.Add(ref count, v));

        var key = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var provider = new FixedKeyProvider(5, new() { [5] = key });
        var encryptor = OrionVaultEncryptor.Create(provider, diag);

        var ct = encryptor.EncryptBytes(new byte[] { 1, 2, 3 });
        encryptor.DecryptBytes(ct);

        Assert.Equal(0, System.Threading.Interlocked.Read(ref count));
    }

    [Fact]
    public void Decrypt_with_non_active_legacy_key_increments_counter()
    {
        var key1 = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var key2 = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);

        // Encrypt under key id 1 (its own diagnostics; we only listen to the decrypt side).
        using var encryptDiag = new OrionVaultDiagnostics();
        var ct = OrionVaultEncryptor
            .Create(new FixedKeyProvider(1, new() { [1] = key1 }), encryptDiag)
            .EncryptBytes(new byte[] { 9, 8, 7 });

        // Decrypt under a provider whose active key is now 2, so key id 1 is legacy.
        using var diag = new OrionVaultDiagnostics();
        long count = 0;
        using var listener = StartIsolatedListener(diag, v => System.Threading.Interlocked.Add(ref count, v));

        var decryptor = OrionVaultEncryptor.Create(
            new FixedKeyProvider(2, new() { [1] = key1, [2] = key2 }), diag);
        decryptor.DecryptBytes(ct);

        Assert.Equal(1, System.Threading.Interlocked.Read(ref count));
    }
}
