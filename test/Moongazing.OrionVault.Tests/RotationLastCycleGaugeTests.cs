namespace Moongazing.OrionVault.Tests;

using System.Diagnostics.Metrics;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.Rotation;
using Xunit;

public sealed class RotationLastCycleGaugeTests
{
    private sealed class StubSource : IRotationSource<int>
    {
        public Dictionary<int, byte[]> Rows { get; } = new();
#pragma warning disable CS1998
        public async IAsyncEnumerable<RotationCandidate<int>> EnumerateAsync(
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            foreach (var pair in Rows)
            {
                yield return new RotationCandidate<int>(pair.Key, pair.Value);
            }
        }
#pragma warning restore CS1998
        public Task UpdateAsync(int handle, byte[] ciphertext, CancellationToken cancellationToken)
        {
            Rows[handle] = ciphertext;
            return Task.CompletedTask;
        }
    }

    private static string FreshKey() => Convert.ToBase64String(
        System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

    [Fact]
    public async Task After_RunCycleAsync_last_cycle_gauges_reflect_the_just_completed_cycle()
    {
        var source = new StubSource();
        var k1 = FreshKey();
        var k2 = FreshKey();
        var seedServices = new ServiceCollection();
        seedServices.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => { k.Add(1, k1); k.Add(2, k2); });
            o.ActiveKeyId = 1;
        });
        await using (var seed = seedServices.BuildServiceProvider())
        {
            var enc = seed.GetRequiredService<IEncryptor>();
            // Seed two rows; only ONE will need rotation against active key 2 (the
            // already-active row stays as a control that does not pollute the rotated count).
            source.Rows[10] = enc.EncryptBytes(new byte[] { 1, 2, 3 });
        }

        var rotated = 0L;
        var scanned = 0L;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name != OrionVaultDiagnostics.MeterName) return;
            if (instrument.Name == "orionvault.rotation.last_cycle.rotated"
                || instrument.Name == "orionvault.rotation.last_cycle.scanned")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, val, _, _) =>
        {
            // Test isolation: a prior test's OrionVaultDiagnostics singleton may still
            // have its (disposed) Meter in process and its (zero-valued) gauges firing
            // alongside the host's. Using Math.Max keeps the larger value so the post-
            // sweep snapshot wins over any leftover zero-emitting gauges.
            if (instrument.Name == "orionvault.rotation.last_cycle.rotated")
            {
                long current;
                do { current = Interlocked.Read(ref rotated); }
                while (val > current && Interlocked.CompareExchange(ref rotated, val, current) != current);
            }
            if (instrument.Name == "orionvault.rotation.last_cycle.scanned")
            {
                long current;
                do { current = Interlocked.Read(ref scanned); }
                while (val > current && Interlocked.CompareExchange(ref scanned, val, current) != current);
            }
        });
        listener.Start();

        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => { k.Add(1, k1); k.Add(2, k2); });
            o.ActiveKeyId = 2;
        });
        services.AddSingleton<IRotationSource<int>>(source);
        await using var sp = services.BuildServiceProvider();
        using var sut = new EncryptionRotationHostedService<int>(
            sp.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new EncryptionRotationOptions()));

        await sut.RunCycleAsync(CancellationToken.None);

        // Force observable callbacks to fire so the listener captures the snapshot.
        listener.RecordObservableInstruments();

        Assert.Equal(1, Interlocked.Read(ref scanned));
        Assert.Equal(1, Interlocked.Read(ref rotated));
    }
}
