namespace Moongazing.OrionVault.Tests;

using System.Diagnostics.Metrics;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Diagnostics;
using Xunit;

public sealed class ActiveKeyIdGaugeTests
{
    [Fact]
    public void Gauge_reports_the_configured_active_key_id_after_AddOrionVault()
    {
        long observed = 0;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == OrionVaultDiagnostics.MeterName
                && instrument.Name == "orionvault.active_key_id")
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
            o.UseStaticKeys(k => k.Add(7, System.Convert.ToBase64String(
                System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))));
            o.ActiveKeyId = 7;
        });
        using var sp = services.BuildServiceProvider();
        _ = sp.GetRequiredService<OrionVaultDiagnostics>();

        listener.RecordObservableInstruments();

        Assert.Equal(7L, System.Threading.Interlocked.Read(ref observed));
    }
}
