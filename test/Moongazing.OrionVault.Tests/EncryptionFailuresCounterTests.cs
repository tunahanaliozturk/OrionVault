namespace Moongazing.OrionVault.Tests;

using System.Diagnostics.Metrics;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.Exceptions;
using Xunit;

public sealed class EncryptionFailuresCounterTests
{
    [Fact]
    public void Encrypt_with_unregistered_active_key_increments_failures_with_key_not_found_reason()
    {
        var samples = new System.Collections.Generic.List<string>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == OrionVaultDiagnostics.MeterName
                && instrument.Name == "orionvault.encryption.failures")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            foreach (var t in tags)
            {
                if (t.Key == "reason" && t.Value is string s) { lock (samples) { samples.Add(s); } }
            }
        });
        listener.Start();

        // A provider whose ActiveKeyId is NOT registered - the config-time validation in
        // AddOrionVault cannot run here because we build the encryptor directly, so the
        // failure surfaces at encrypt-time LookupKey (the production safety net).
        using var diag = new OrionVaultDiagnostics();
        var encryptor = OrionVaultEncryptor.Create(new MisconfiguredProvider(), diag);

        Assert.Throws<OrionVaultKeyNotFoundException>(() => encryptor.EncryptBytes(new byte[] { 1, 2, 3 }));

        lock (samples)
        {
            Assert.Contains("key_not_found", samples);
        }
    }

    // ActiveKeyId points at an id TryGetKey never returns - the encrypt-time
    // OrionVaultKeyNotFoundException path that the v0.2.26 counter instruments.
    private sealed class MisconfiguredProvider : IKeyProvider
    {
        public short ActiveKeyId => 2;
        public int KeyCount => 0;
        public System.ReadOnlyMemory<byte>? TryGetKey(short keyId) => null;
    }
}
