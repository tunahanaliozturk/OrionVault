namespace Moongazing.OrionVault.Tests;

using System.Diagnostics.Metrics;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Diagnostics;
using Xunit;

public sealed class KeyResolutionDurationTests
{
    [Fact]
    public void EncryptBytes_records_key_resolution_duration_with_hit_tag()
    {
        var samples = new System.Collections.Generic.List<(double ms, string outcome)>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == OrionVaultDiagnostics.MeterName
                && instrument.Name == "orionvault.key_resolution.duration_ms")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<double>((_, val, tags, _) =>
        {
            string outcome = string.Empty;
            foreach (var t in tags)
            {
                if (t.Key == "outcome" && t.Value is string s) { outcome = s; }
            }
            lock (samples) { samples.Add((val, outcome)); }
        });
        listener.Start();

        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, System.Convert.ToBase64String(
                System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))));
            o.ActiveKeyId = 1;
        });
        using var sp = services.BuildServiceProvider();
        var encryptor = sp.GetRequiredService<IEncryptor>();
        encryptor.EncryptBytes(new byte[] { 1, 2, 3 });

        lock (samples)
        {
            Assert.Contains(samples, s => s.outcome == "hit");
        }
    }
}
