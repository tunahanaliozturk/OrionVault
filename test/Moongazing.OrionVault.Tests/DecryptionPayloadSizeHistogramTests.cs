namespace Moongazing.OrionVault.Tests;

using System.Diagnostics.Metrics;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Diagnostics;
using Xunit;

public sealed class DecryptionPayloadSizeHistogramTests
{
    [Fact]
    public void DecryptBytes_records_the_plaintext_size_on_the_decryption_histogram()
    {
        long observed = 0;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name != OrionVaultDiagnostics.MeterName) return;
            if (instrument.Name == "orionvault.decryption.payload_size_bytes")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<int>((_, val, _, _) =>
        {
            long current;
            do { current = Interlocked.Read(ref observed); }
            while (val > current && Interlocked.CompareExchange(ref observed, val, current) != current);
        });
        listener.Start();

        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))));
            o.ActiveKeyId = 1;
        });
        var sp = services.BuildServiceProvider();
        try
        {
            var encryptor = sp.GetRequiredService<IEncryptor>();
            var plaintext = new byte[] { 10, 20, 30, 40, 50, 60, 70 };
            var ciphertext = encryptor.EncryptBytes(plaintext);
            encryptor.DecryptBytes(ciphertext);
        }
        finally
        {
            sp.Dispose();
        }

        Assert.True(Interlocked.Read(ref observed) >= 7);
    }
}
