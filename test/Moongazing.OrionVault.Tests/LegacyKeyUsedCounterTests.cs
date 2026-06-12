namespace Moongazing.OrionVault.Tests;

using System.Diagnostics.Metrics;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Diagnostics;
using Xunit;

public sealed class LegacyKeyUsedCounterTests
{
    [Fact]
    public void Decrypt_with_active_key_does_NOT_increment_legacy_counter()
    {
        long count = 0;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == OrionVaultDiagnostics.MeterName
                && instrument.Name == "orionvault.decryption.legacy_key_used")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, val, _, _) => System.Threading.Interlocked.Add(ref count, val));
        listener.Start();

        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(5, System.Convert.ToBase64String(
                System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))));
            o.ActiveKeyId = 5;
        });
        using var sp = services.BuildServiceProvider();
        var encryptor = sp.GetRequiredService<IEncryptor>();

        var ct = encryptor.EncryptBytes(new byte[] { 1, 2, 3 });
        encryptor.DecryptBytes(ct);

        Assert.Equal(0, System.Threading.Interlocked.Read(ref count));
    }

    [Fact]
    public void Decrypt_with_non_active_legacy_key_increments_counter()
    {
        long count = 0;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == OrionVaultDiagnostics.MeterName
                && instrument.Name == "orionvault.decryption.legacy_key_used")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, val, _, _) => System.Threading.Interlocked.Add(ref count, val));
        listener.Start();

        // Use TWO keys: encrypt under id=1, rotate by setting ActiveKeyId=2,
        // decrypt the original ciphertext - it resolves via key id 1 (legacy).
        var key1 = System.Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var key2 = System.Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

        // First setup: ActiveKeyId = 1
        var services1 = new ServiceCollection();
        services1.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => { k.Add(1, key1); k.Add(2, key2); });
            o.ActiveKeyId = 1;
        });
        using var sp1 = services1.BuildServiceProvider();
        var ct = sp1.GetRequiredService<IEncryptor>().EncryptBytes(new byte[] { 9, 8, 7 });

        // Rotated setup: ActiveKeyId = 2; key id 1 is now LEGACY
        var services2 = new ServiceCollection();
        services2.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => { k.Add(1, key1); k.Add(2, key2); });
            o.ActiveKeyId = 2;
        });
        using var sp2 = services2.BuildServiceProvider();
        sp2.GetRequiredService<IEncryptor>().DecryptBytes(ct);

        Assert.Equal(1, System.Threading.Interlocked.Read(ref count));
    }
}
