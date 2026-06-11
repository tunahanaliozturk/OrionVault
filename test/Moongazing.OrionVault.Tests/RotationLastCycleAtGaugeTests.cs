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

public sealed class RotationLastCycleAtGaugeTests
{
    private sealed class EmptySource : IRotationSource<int>
    {
#pragma warning disable CS1998
        public async IAsyncEnumerable<RotationCandidate<int>> EnumerateAsync(
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            yield break;
        }
#pragma warning restore CS1998
        public Task UpdateAsync(int handle, byte[] ciphertext, CancellationToken cancellationToken)
            => Task.CompletedTask;
    }

    [Fact]
    public async Task After_RunCycleAsync_the_last_cycle_timestamp_gauge_is_non_zero()
    {
        // Use a max-wins reduction over the observable callback so leftover gauges from
        // earlier diagnostics instances do not overwrite the post-sweep snapshot. Matches
        // the v0.2.15 RotationLastCycleGauge test pattern.
        long observed = 0;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name != OrionVaultDiagnostics.MeterName) return;
            if (instrument.Name == "orionvault.rotation.last_cycle_at_unix_seconds")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, val, _, _) =>
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
        services.AddSingleton<IRotationSource<int>>(new EmptySource());
        await using var sp = services.BuildServiceProvider();
        using var sut = new EncryptionRotationHostedService<int>(
            sp.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new EncryptionRotationOptions()));

        await sut.RunCycleAsync(CancellationToken.None);

        listener.RecordObservableInstruments();

        var nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        // Just-completed cycle should report a timestamp within the last 5 seconds.
        Assert.InRange(Interlocked.Read(ref observed), nowUnix - 5, nowUnix + 5);
    }
}
