namespace Moongazing.OrionVault.AzureKeyVault.Tests;

using System.Text;
using Azure;
using Moongazing.OrionVault.AzureKeyVault;
using Moongazing.OrionVault.Caching;
using Moongazing.OrionVault.Exceptions;
using Moq;
using Xunit;

public sealed class AzureKeyVaultKeyProviderTests
{
    private static byte[] Key32(byte fill)
    {
        var bytes = new byte[32];
        Array.Fill(bytes, fill);
        return bytes;
    }

    [Fact]
    public void Constructor_throws_when_active_id_not_in_map()
    {
        var keys = new Dictionary<short, ReadOnlyMemory<byte>>
        {
            [1] = Key32(0x11),
        };

        Assert.Throws<OrionVaultConfigurationException>(
            () => new AzureKeyVaultKeyProvider(activeKeyId: 7, plaintextKeys: keys));
    }

    [Fact]
    public void Constructor_throws_when_any_key_is_not_32_bytes()
    {
        var keys = new Dictionary<short, ReadOnlyMemory<byte>>
        {
            [1] = new byte[16],
        };

        var ex = Assert.Throws<OrionVaultConfigurationException>(
            () => new AzureKeyVaultKeyProvider(activeKeyId: 1, plaintextKeys: keys));
        Assert.Contains("32", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TryGetKey_returns_registered_key_and_null_for_unknown()
    {
        var keyOne = Key32(0x11);
        var sut = new AzureKeyVaultKeyProvider(activeKeyId: 1, new Dictionary<short, ReadOnlyMemory<byte>>
        {
            [1] = keyOne,
        });

        Assert.Equal(1, sut.ActiveKeyId);
        Assert.True(keyOne.AsSpan().SequenceEqual(sut.TryGetKey(1)!.Value.Span));
        Assert.Null(sut.TryGetKey(99));
    }

    [Fact]
    public async Task CreateAsync_unwraps_each_configured_blob_via_unwrap_client()
    {
        var client = new Mock<IKeyVaultUnwrapClient>();
        var key1 = Key32(0x11);
        var key2 = Key32(0x22);
        client.Setup(c => c.UnwrapAsync(It.Is<byte[]>(b => Encoding.ASCII.GetString(b) == "ct1"), It.IsAny<CancellationToken>()))
            .ReturnsAsync(key1);
        client.Setup(c => c.UnwrapAsync(It.Is<byte[]>(b => Encoding.ASCII.GetString(b) == "ct2"), It.IsAny<CancellationToken>()))
            .ReturnsAsync(key2);

        var opts = new AzureKeyVaultKeyProviderOptions { KeyName = "orionvault-kek", ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));
        opts.WrappedKeys[2] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct2"));

        var sut = await AzureKeyVaultKeyProvider.CreateAsync(client.Object, opts);

        Assert.Equal(1, sut.ActiveKeyId);
        Assert.True(key1.AsSpan().SequenceEqual(sut.TryGetKey(1)!.Value.Span));
        Assert.True(key2.AsSpan().SequenceEqual(sut.TryGetKey(2)!.Value.Span));
        client.Verify(c => c.UnwrapAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    [Fact]
    public async Task CreateAsync_throws_when_WrappedKeys_is_empty()
    {
        var client = new Mock<IKeyVaultUnwrapClient>();
        var opts = new AzureKeyVaultKeyProviderOptions { KeyName = "orionvault-kek", ActiveKeyId = 1 };

        await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => AzureKeyVaultKeyProvider.CreateAsync(client.Object, opts));
    }

    [Fact]
    public async Task CreateAsync_throws_when_KeyName_is_blank()
    {
        var client = new Mock<IKeyVaultUnwrapClient>();
        var opts = new AzureKeyVaultKeyProviderOptions { KeyName = "  ", ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(new byte[] { 1, 2, 3 });

        var ex = await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => AzureKeyVaultKeyProvider.CreateAsync(client.Object, opts));
        Assert.Contains("KeyName", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateAsync_throws_when_ciphertext_is_not_base64()
    {
        var client = new Mock<IKeyVaultUnwrapClient>();
        var opts = new AzureKeyVaultKeyProviderOptions { KeyName = "orionvault-kek", ActiveKeyId = 1 };
        opts.WrappedKeys[1] = "not-base64-!!";

        var ex = await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => AzureKeyVaultKeyProvider.CreateAsync(client.Object, opts));
        Assert.Contains("base64", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateAsync_throws_when_ciphertext_is_whitespace()
    {
        var client = new Mock<IKeyVaultUnwrapClient>();
        var opts = new AzureKeyVaultKeyProviderOptions { KeyName = "orionvault-kek", ActiveKeyId = 1 };
        opts.WrappedKeys[1] = "   ";

        await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => AzureKeyVaultKeyProvider.CreateAsync(client.Object, opts));
    }

    [Fact]
    public async Task CreateAsync_throws_when_decoded_ciphertext_is_zero_bytes()
    {
        var client = new Mock<IKeyVaultUnwrapClient>();
        var opts = new AzureKeyVaultKeyProviderOptions { KeyName = "orionvault-kek", ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(Array.Empty<byte>());

        await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => AzureKeyVaultKeyProvider.CreateAsync(client.Object, opts));
    }

    // ---- envelope-key cache adapter: classification + reload-aware refresh ----

    [Fact]
    public void CreateUnwrappedKeySource_null_guards_its_arguments()
    {
        var opts = new AzureKeyVaultKeyProviderOptions { KeyName = "orionvault-kek", ActiveKeyId = 1 };
        Assert.Throws<ArgumentNullException>(
            () => AzureKeyVaultKeyProvider.CreateUnwrappedKeySource(null!, opts));
        Assert.Throws<ArgumentNullException>(
            () => AzureKeyVaultKeyProvider.CreateUnwrappedKeySource(Mock.Of<IKeyVaultUnwrapClient>(), null!));
    }

    [Theory]
    [InlineData(403)] // access policy / RBAC assignment removed
    [InlineData(404)] // key deleted or never existed
    [InlineData(409)] // key disabled or soft-deleted
    public void TryClassify_maps_revocation_class_statuses_to_Revocation(int status)
    {
        var classified = AzureKeyVaultKeyProvider.TryClassify(new RequestFailedException(status, "denied"));
        Assert.NotNull(classified);
        Assert.Equal(KeyUnwrapFailureKind.Revocation, classified!.Kind);
    }

    [Theory]
    [InlineData(429)] // throttled
    [InlineData(500)]
    [InlineData(503)]
    public void TryClassify_maps_other_statuses_to_Transient(int status)
    {
        var classified = AzureKeyVaultKeyProvider.TryClassify(new RequestFailedException(status, "blip"));
        Assert.NotNull(classified);
        Assert.Equal(KeyUnwrapFailureKind.Transient, classified!.Kind);
    }

    [Fact]
    public void TryClassify_returns_null_for_non_azure_exception()
        => Assert.Null(AzureKeyVaultKeyProvider.TryClassify(new InvalidOperationException("not Azure")));

    [Fact]
    public void Cache_refresh_re_runs_vault_unwrap_and_picks_up_rotated_key()
    {
        // A reload-aware refresh: after the TTL elapses the adapter re-runs UnwrapAsync, so a
        // vault-side rotation (different plaintext for the same ciphertext) is honoured.
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var unwrapCalls = 0;
        var client = FakeUnwrapClient(() =>
        {
            var call = Interlocked.Increment(ref unwrapCalls);
            return call == 1 ? Key32(0x11) : Key32(0x22);
        });

        var opts = new AzureKeyVaultKeyProviderOptions { KeyName = "orionvault-kek", ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));

        var source = AzureKeyVaultKeyProvider.CreateUnwrappedKeySource(client, opts);
        using var cache = new CachingKeyProvider(source, CacheOpts(TimeSpan.FromMinutes(15)), time);

        Assert.True(Key32(0x11).AsSpan().SequenceEqual(cache.TryGetKey(1)!.Value.Span));
        Assert.Equal(1, unwrapCalls);

        time.Advance(TimeSpan.FromMinutes(15));

        Assert.True(Key32(0x22).AsSpan().SequenceEqual(cache.TryGetKey(1)!.Value.Span));
        Assert.Equal(2, unwrapCalls); // the refresh actually re-unwrapped
    }

    [Fact]
    public void Cache_fails_closed_when_refresh_hits_a_revoked_key_even_with_serve_stale()
    {
        // The incident-response case: the operator removes the vault access policy. Without this
        // seam the unwrap-once provider keeps the plaintext key for the whole process lifetime and
        // the revoked key goes on encrypting and decrypting until someone restarts the host.
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var calls = 0;
        var client = FakeUnwrapClient(() =>
        {
            var call = Interlocked.Increment(ref calls);
            if (call == 1)
            {
                return Key32(0x11);
            }
            throw new RequestFailedException(403, "caller is not authorized to perform action on resource");
        });

        var opts = new AzureKeyVaultKeyProviderOptions { KeyName = "orionvault-kek", ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));

        var source = AzureKeyVaultKeyProvider.CreateUnwrappedKeySource(client, opts);
        using var cache = new CachingKeyProvider(source, CacheOpts(TimeSpan.FromMinutes(15), serveStale: true), time);

        Assert.NotNull(cache.TryGetKey(1)); // prime ok
        time.Advance(TimeSpan.FromMinutes(20));

        // Serve-stale is ON, but a revocation must fail closed rather than serve the cached key.
        var ex = Assert.Throws<KeyUnwrapException>(() => cache.TryGetKey(1));
        Assert.Equal(KeyUnwrapFailureKind.Revocation, ex.Kind);
    }

    [Fact]
    public void Cache_serves_stale_through_a_transient_refresh_failure()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var calls = 0;
        var client = FakeUnwrapClient(() =>
        {
            var call = Interlocked.Increment(ref calls);
            if (call == 1)
            {
                return Key32(0x11);
            }
            throw new RequestFailedException(503, "vault unavailable");
        });

        var opts = new AzureKeyVaultKeyProviderOptions { KeyName = "orionvault-kek", ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));

        var source = AzureKeyVaultKeyProvider.CreateUnwrappedKeySource(client, opts);
        using var cache = new CachingKeyProvider(source, CacheOpts(TimeSpan.FromMinutes(15), serveStale: true), time);

        Assert.True(Key32(0x11).AsSpan().SequenceEqual(cache.TryGetKey(1)!.Value.Span));
        time.Advance(TimeSpan.FromMinutes(20));

        // Transient fault with serve-stale: last-good key keeps decrypting.
        Assert.True(Key32(0x11).AsSpan().SequenceEqual(cache.TryGetKey(1)!.Value.Span));
        Assert.True(calls >= 2);
    }

    private static EnvelopeKeyCacheOptions CacheOpts(TimeSpan ttl, bool serveStale = true)
        => new() { Enabled = true, Ttl = ttl, ServeStaleOnRefreshFailure = serveStale };

    // A synchronous throw from the func surfaces as a faulted task exactly as a real Azure SDK
    // fault would, without a broad catch in the seam.
    private static IKeyVaultUnwrapClient FakeUnwrapClient(Func<byte[]> unwrap)
    {
        var client = new Mock<IKeyVaultUnwrapClient>();
        client.Setup(c => c.UnwrapAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .Returns((byte[] _, CancellationToken _) => Task.FromResult(unwrap()));
        return client.Object;
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset now;

        public ManualTimeProvider(DateTimeOffset start) => now = start;

        public override DateTimeOffset GetUtcNow() => now;

        public void Advance(TimeSpan by) => now = now.Add(by);
    }
}
