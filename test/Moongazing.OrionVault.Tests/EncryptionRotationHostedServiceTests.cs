namespace Moongazing.OrionVault.Tests;

using System.Runtime.CompilerServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Rotation;
using Xunit;

public sealed class EncryptionRotationHostedServiceTests
{
    private sealed class InMemoryRotationSource : IRotationSource<int>
    {
        public Dictionary<int, byte[]> Rows { get; } = new();
        public List<(int Handle, byte[] Fresh)> Updates { get; } = new();
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
            Updates.Add((handle, ciphertext));
            return Task.CompletedTask;
        }
    }

    private const string KeyBase64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    private static (ServiceProvider sp, InMemoryRotationSource source) BuildHost(short activeKeyId)
    {
        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k =>
            {
                k.Add(1, KeyBase64);
                k.Add(2, Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));
            });
            o.ActiveKeyId = activeKeyId;
        });
        var source = new InMemoryRotationSource();
        services.AddSingleton<IRotationSource<int>>(source);
        var sp = services.BuildServiceProvider();
        return (sp, source);
    }

    private static EncryptionRotationHostedService<int> NewHost(ServiceProvider sp, EncryptionRotationOptions? opts = null)
        => new(
            sp.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(opts ?? new EncryptionRotationOptions()));

    [Fact]
    public async Task RunCycleAsync_rotates_rows_on_a_non_active_key_and_skips_rows_on_active_key()
    {
        // Encrypt under key id 1 first, then bump active to 2 to require rotation.
        var (firstSp, source) = BuildHost(activeKeyId: 1);
        try
        {
            var encryptor = firstSp.GetRequiredService<IEncryptor>();
            source.Rows[10] = encryptor.EncryptBytes(new byte[] { 1, 2, 3 });
        }
        finally
        {
            await firstSp.DisposeAsync();
        }

        // Build a NEW host whose active key id is 2.
        var (sp, _) = BuildHost(activeKeyId: 2);
        // Wire the same source we just seeded.
        var collection = new ServiceCollection();
        collection.AddOrionVault(o =>
        {
            o.UseStaticKeys(k =>
            {
                k.Add(1, KeyBase64);
                k.Add(2, Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));
            });
            o.ActiveKeyId = 2;
        });
        collection.AddSingleton<IRotationSource<int>>(source);
        await using var hostSp = collection.BuildServiceProvider();
        using var sut = NewHost(hostSp);

        var result = await sut.RunCycleAsync(CancellationToken.None);

        Assert.Equal(1, result.Scanned);
        Assert.Equal(1, result.Rotated);
        Assert.Equal(0, result.Skipped);
        Assert.Single(source.Updates);

        // The freshly rotated ciphertext should now read back under the new active key.
        var afterEncryptor = hostSp.GetRequiredService<IEncryptor>();
        Assert.Equal(new byte[] { 1, 2, 3 }, afterEncryptor.DecryptBytes(source.Updates[0].Fresh));
    }

    [Fact]
    public async Task RunCycleAsync_skips_rows_already_on_active_key()
    {
        var (sp, source) = BuildHost(activeKeyId: 1);
        var encryptor = sp.GetRequiredService<IEncryptor>();
        source.Rows[10] = encryptor.EncryptBytes(new byte[] { 9, 9 });

        using var sut = NewHost(sp);
        var result = await sut.RunCycleAsync(CancellationToken.None);

        Assert.Equal(1, result.Scanned);
        Assert.Equal(0, result.Rotated);
        Assert.Equal(1, result.Skipped);
        Assert.Empty(source.Updates);
        await sp.DisposeAsync();
    }

    [Fact]
    public async Task RunCycleAsync_caps_rotations_at_MaxRowsPerCycle()
    {
        // Three rows all on the previous key.
        var (firstSp, source) = BuildHost(activeKeyId: 1);
        try
        {
            var encryptor = firstSp.GetRequiredService<IEncryptor>();
            source.Rows[1] = encryptor.EncryptBytes(new byte[] { 1 });
            source.Rows[2] = encryptor.EncryptBytes(new byte[] { 2 });
            source.Rows[3] = encryptor.EncryptBytes(new byte[] { 3 });
        }
        finally
        {
            await firstSp.DisposeAsync();
        }

        var collection = new ServiceCollection();
        collection.AddOrionVault(o =>
        {
            o.UseStaticKeys(k =>
            {
                k.Add(1, KeyBase64);
                k.Add(2, Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));
            });
            o.ActiveKeyId = 2;
        });
        collection.AddSingleton<IRotationSource<int>>(source);
        await using var hostSp = collection.BuildServiceProvider();
        using var sut = NewHost(hostSp, new EncryptionRotationOptions { MaxRowsPerCycle = 2 });

        var result = await sut.RunCycleAsync(CancellationToken.None);

        Assert.Equal(2, result.Rotated);
    }

    [Fact]
    public void Options_validate_at_construction()
    {
        var (sp, _) = BuildHost(activeKeyId: 1);
        try
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                NewHost(sp, new EncryptionRotationOptions { Interval = TimeSpan.Zero }));
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                NewHost(sp, new EncryptionRotationOptions { MaxRowsPerCycle = 0 }));
        }
        finally
        {
            sp.Dispose();
        }
    }
}
