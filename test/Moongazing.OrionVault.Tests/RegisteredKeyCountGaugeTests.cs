namespace Moongazing.OrionVault.Tests;

using System.Diagnostics.Metrics;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Diagnostics;
using Xunit;

public sealed class RegisteredKeyCountGaugeTests
{
    [Fact]
    public void Gauge_reports_the_static_provider_key_count_after_encryptor_resolution()
    {
        long observed = -100;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == OrionVaultDiagnostics.MeterName
                && instrument.Name == "orion.vault.keys.registered_count")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, val, _, _) =>
        {
            long current;
            do { current = System.Threading.Interlocked.Read(ref observed); }
            while (val > current && System.Threading.Interlocked.CompareExchange(ref observed, val, current) != current);
        });
        listener.Start();

        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k =>
            {
                k.Add(1, System.Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));
                k.Add(2, System.Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));
                k.Add(3, System.Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));
            });
            o.ActiveKeyId = 3;
        });
        using var sp = services.BuildServiceProvider();
        _ = sp.GetRequiredService<IEncryptor>();
        listener.RecordObservableInstruments();

        Assert.Equal(3, System.Threading.Interlocked.Read(ref observed));
    }

    [Fact]
    public void Default_interface_KeyCount_returns_minus_one_for_non_enumerable_providers()
    {
        var sut = new NonEnumerableProvider();
        Assert.Equal(-1, ((IKeyProvider)sut).KeyCount);
    }

    private sealed class NonEnumerableProvider : IKeyProvider
    {
        public short ActiveKeyId => 1;
        public System.ReadOnlyMemory<byte>? TryGetKey(short keyId) => null;
        // KeyCount intentionally NOT overridden - exercises the DIM default of -1.
    }
}
