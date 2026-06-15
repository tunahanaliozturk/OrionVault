namespace Moongazing.OrionVault.Tests;

using System.Diagnostics.Metrics;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.Exceptions;
using Xunit;

public sealed class AuthTagFailuresCounterTests
{
    private const string InstrumentName = "orionvault.decryption.auth_tag_failures";

    private static (IEncryptor Encryptor, ServiceProvider Sp) BuildEncryptor()
    {
        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, System.Convert.ToBase64String(
                System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))));
            o.ActiveKeyId = 1;
        });
        var sp = services.BuildServiceProvider();
        return (sp.GetRequiredService<IEncryptor>(), sp);
    }

    private static MeterListener StartListener(System.Action<long> add)
    {
        var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == OrionVaultDiagnostics.MeterName && instrument.Name == InstrumentName)
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
        long total = 0;
        using var listener = StartListener(v => System.Threading.Interlocked.Add(ref total, v));

        var (encryptor, sp) = BuildEncryptor();
        using var _ = sp;

        var ciphertext = encryptor.EncryptBytes(new byte[] { 1, 2, 3 });
        // Flip a byte in the tag region so AES-GCM authentication fails.
        ciphertext[ciphertext.Length - 1] ^= 0xff;

        Assert.Throws<OrionVaultDecryptionException>(() => encryptor.DecryptBytes(ciphertext));
        Assert.Equal(1L, System.Threading.Interlocked.Read(ref total));
    }

    [Fact]
    public void A_valid_decrypt_does_not_increment_auth_tag_failures()
    {
        long total = 0;
        using var listener = StartListener(v => System.Threading.Interlocked.Add(ref total, v));

        var (encryptor, sp) = BuildEncryptor();
        using var _ = sp;

        var ciphertext = encryptor.EncryptBytes(new byte[] { 1, 2, 3 });
        var plaintext = encryptor.DecryptBytes(ciphertext);

        Assert.Equal(new byte[] { 1, 2, 3 }, plaintext);
        Assert.Equal(0L, System.Threading.Interlocked.Read(ref total));
    }
}
