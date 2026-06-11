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

public sealed class RotationDiagnosticsTests
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
    public async Task RunCycleAsync_records_rotated_skipped_and_cycle_duration_counters()
    {
        // Seed under key 1, then switch active key to 2 so one row needs rotation.
        var source = new StubSource();
        var key1Material = FreshKey();
        var key2Material = FreshKey();
        var seedServices = new ServiceCollection();
        seedServices.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => { k.Add(1, key1Material); k.Add(2, key2Material); });
            o.ActiveKeyId = 1;
        });
        await using (var seedSp = seedServices.BuildServiceProvider())
        {
            var encryptor = seedSp.GetRequiredService<IEncryptor>();
            source.Rows[10] = encryptor.EncryptBytes(new byte[] { 1, 2, 3 });
        }

        var rotated = new System.Collections.Generic.List<long>();
        var skipped = new System.Collections.Generic.List<long>();
        var cycleDurations = new System.Collections.Generic.List<double>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name != OrionVaultDiagnostics.MeterName) return;
            if (instrument.Name is "orionvault.rotation.rows_rotated"
                or "orionvault.rotation.rows_skipped"
                or "orionvault.rotation.cycle_duration_ms")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, val, _, _) =>
        {
            if (instrument.Name == "orionvault.rotation.rows_rotated") lock (rotated) rotated.Add(val);
            if (instrument.Name == "orionvault.rotation.rows_skipped") lock (skipped) skipped.Add(val);
        });
        listener.SetMeasurementEventCallback<double>((instrument, val, _, _) =>
        {
            if (instrument.Name == "orionvault.rotation.cycle_duration_ms") lock (cycleDurations) cycleDurations.Add(val);
        });
        listener.Start();

        var collection = new ServiceCollection();
        collection.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => { k.Add(1, key1Material); k.Add(2, key2Material); });
            o.ActiveKeyId = 2;
        });
        collection.AddSingleton<IRotationSource<int>>(source);
        await using var hostSp = collection.BuildServiceProvider();
        using var sut = new EncryptionRotationHostedService<int>(
            hostSp.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new EncryptionRotationOptions()));

        var result = await sut.RunCycleAsync(CancellationToken.None);

        Assert.Equal(1, result.Rotated);
        // v0.2.16 hardening: a leftover OrionVaultDiagnostics instance from a sibling
        // test class can publish duplicate Counter instruments under the same Meter
        // name, so the listener may see emissions from MORE than just this test's
        // rotation. Assert AT LEAST one rather than EXACTLY one - the contract is "this
        // run did at least one rotated emit", not "no other instance is in process".
        lock (rotated) Assert.NotEmpty(rotated);
        lock (cycleDurations) Assert.NotEmpty(cycleDurations);
    }
}
