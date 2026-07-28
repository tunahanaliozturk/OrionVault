namespace Moongazing.OrionVault.Tests;

using System.Diagnostics.Metrics;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Diagnostics;
using Xunit;

public sealed class EncryptionPayloadSizeHistogramTests
{
    [Fact]
    public void EncryptBytes_records_the_plaintext_size_on_the_payload_size_histogram()
    {
        // Max-wins reduction so leftover seed-side diagnostics instances (from sibling
        // test classes) do not overwrite our observed sample.
        long observed = 0;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name != OrionVaultDiagnostics.MeterName) return;
            if (instrument.Name == "orion.vault.encryption.payload_size_bytes")
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
            encryptor.EncryptBytes(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 });
        }
        finally
        {
            sp.Dispose();
        }

        Assert.True(Interlocked.Read(ref observed) >= 12);
    }
}
