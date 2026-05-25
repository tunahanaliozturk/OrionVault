namespace Moongazing.OrionVault.Tests.Diagnostics;

using System.Diagnostics.Metrics;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Exceptions;
using Xunit;

public class OrionVaultDiagnosticsTests
{
    private const string Key32B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    [Fact]
    public void Encrypt_increments_encryptions_counter()
    {
        long encryptions = 0;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (inst, l) =>
        {
            if (inst.Meter.Name == OrionVaultDiagnostics.MeterName &&
                inst.Name == "orionvault.encryptions")
                l.EnableMeasurementEvents(inst);
        };
        listener.SetMeasurementEventCallback<long>((_, val, _, _) => Interlocked.Add(ref encryptions, val));
        listener.Start();

        var sp = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(1, Key32B64));
                o.ActiveKeyId = 1;
            })
            .Services
            .BuildServiceProvider();
        var enc = sp.GetRequiredService<IEncryptor>();
        enc.EncryptString("a");
        enc.EncryptString("b");

        listener.RecordObservableInstruments();
        Volatile.Read(ref encryptions).Should().BeGreaterOrEqualTo(2);
    }

    [Fact]
    public void Decrypt_failure_increments_failures_counter_with_reason_tag()
    {
        var reasons = new List<string>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (inst, l) =>
        {
            if (inst.Meter.Name == OrionVaultDiagnostics.MeterName &&
                inst.Name == "orionvault.decryption.failures")
                l.EnableMeasurementEvents(inst);
        };
        listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            foreach (var t in tags)
                if (t.Key == "reason" && t.Value is string r) reasons.Add(r);
        });
        listener.Start();

        var sp = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(1, Key32B64));
                o.ActiveKeyId = 1;
            })
            .Services
            .BuildServiceProvider();
        var enc = sp.GetRequiredService<IEncryptor>();
        var ct = enc.EncryptString("x");
        ct[^1] ^= 0xFF;
        try { enc.DecryptString(ct); } catch (OrionVaultDecryptionException) { }

        reasons.Should().Contain("tampered");
    }

    [Fact]
    public void Diagnostics_singleton_is_registered()
    {
        var sp = new ServiceCollection()
            .AddOrionVault(o => { o.UseStaticKeys(k => k.Add(1, Key32B64)); o.ActiveKeyId = 1; })
            .Services
            .BuildServiceProvider();

        sp.GetRequiredService<OrionVaultDiagnostics>().Should().NotBeNull();
    }
}
