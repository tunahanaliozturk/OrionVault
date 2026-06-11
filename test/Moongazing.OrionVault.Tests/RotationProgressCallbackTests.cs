namespace Moongazing.OrionVault.Tests;

using System.Runtime.CompilerServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Rotation;
using Xunit;

public sealed class RotationProgressCallbackTests
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
    public async Task ProgressCallback_receives_RotationCycleResult_when_set()
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
            source.Rows[10] = enc.EncryptBytes(new byte[] { 1, 2, 3 });
        }

        RotationCycleResult? captured = null;
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
            Options.Create(new EncryptionRotationOptions
            {
                ProgressCallback = result => captured = result,
            }));

        await sut.RunCycleAsync(CancellationToken.None);

        Assert.NotNull(captured);
        Assert.Equal(1, captured!.Rotated);
    }

    [Fact]
    public async Task ProgressCallback_exception_does_not_abort_the_cycle()
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
            source.Rows[10] = enc.EncryptBytes(new byte[] { 1, 2, 3 });
        }

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
            Options.Create(new EncryptionRotationOptions
            {
                ProgressCallback = _ => throw new InvalidOperationException("notifier broken"),
            }));

        // The call must return normally - the cycle's load-bearing work has already
        // completed by the time the callback fires.
        var result = await sut.RunCycleAsync(CancellationToken.None);

        Assert.Equal(1, result.Rotated);
    }
}
