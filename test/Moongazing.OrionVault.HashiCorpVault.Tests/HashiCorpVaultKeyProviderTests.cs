namespace Moongazing.OrionVault.HashiCorpVault.Tests;

using System.Net;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Caching;
using Moongazing.OrionVault.Exceptions;
using Moongazing.OrionVault.HashiCorpVault;
using Moq;
using VaultSharp.Core;
using Xunit;

public sealed class HashiCorpVaultKeyProviderTests
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
            () => new HashiCorpVaultKeyProvider(activeKeyId: 7, plaintextKeys: keys));
    }

    [Fact]
    public void Constructor_throws_when_any_key_is_not_32_bytes()
    {
        var keys = new Dictionary<short, ReadOnlyMemory<byte>>
        {
            [1] = new byte[16],
        };

        var ex = Assert.Throws<OrionVaultConfigurationException>(
            () => new HashiCorpVaultKeyProvider(activeKeyId: 1, plaintextKeys: keys));
        Assert.Contains("32", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TryGetKey_returns_registered_key_and_null_for_unknown()
    {
        var keyOne = Key32(0x11);
        var sut = new HashiCorpVaultKeyProvider(activeKeyId: 1, new Dictionary<short, ReadOnlyMemory<byte>>
        {
            [1] = keyOne,
        });

        Assert.Equal(1, sut.ActiveKeyId);
        Assert.Equal(1, sut.KeyCount);
        Assert.True(keyOne.AsSpan().SequenceEqual(sut.TryGetKey(1)!.Value.Span));
        Assert.Null(sut.TryGetKey(99));
    }

    [Fact]
    public void Provider_does_not_implement_IUnwrappedKeySource_directly()
    {
        // The caching layer adapts a raw provider via CreateUnwrappedKeySource; the concrete
        // provider must NOT itself be an IUnwrappedKeySource (mirroring AWS / Azure / GCP shape).
        var sut = new HashiCorpVaultKeyProvider(1, new Dictionary<short, ReadOnlyMemory<byte>> { [1] = Key32(0x11) });
        Assert.IsNotAssignableFrom<IUnwrappedKeySource>(sut);
    }

    [Fact]
    public async Task CreateAsync_decrypts_each_configured_ciphertext_via_decrypt_client()
    {
        var client = new Mock<IVaultTransitDecryptClient>();
        var key1 = Key32(0x11);
        var key2 = Key32(0x22);
        client.Setup(c => c.DecryptAsync("vault:v1:ct1", It.IsAny<CancellationToken>())).ReturnsAsync(key1);
        client.Setup(c => c.DecryptAsync("vault:v1:ct2", It.IsAny<CancellationToken>())).ReturnsAsync(key2);

        var opts = new HashiCorpVaultKeyProviderOptions { TransitKeyName = "orionvault", ActiveKeyId = 1 };
        opts.WrappedKeys[1] = "vault:v1:ct1";
        opts.WrappedKeys[2] = "vault:v1:ct2";

        var sut = await HashiCorpVaultKeyProvider.CreateAsync(client.Object, opts);

        Assert.Equal(1, sut.ActiveKeyId);
        Assert.True(key1.AsSpan().SequenceEqual(sut.TryGetKey(1)!.Value.Span));
        Assert.True(key2.AsSpan().SequenceEqual(sut.TryGetKey(2)!.Value.Span));
        client.Verify(c => c.DecryptAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    [Fact]
    public async Task CreateAsync_throws_when_WrappedKeys_is_empty()
    {
        var client = new Mock<IVaultTransitDecryptClient>();
        var opts = new HashiCorpVaultKeyProviderOptions { TransitKeyName = "orionvault", ActiveKeyId = 1 };

        await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => HashiCorpVaultKeyProvider.CreateAsync(client.Object, opts));
    }

    [Fact]
    public async Task CreateAsync_throws_when_TransitKeyName_is_blank()
    {
        var client = new Mock<IVaultTransitDecryptClient>();
        var opts = new HashiCorpVaultKeyProviderOptions { TransitKeyName = "  ", ActiveKeyId = 1 };
        opts.WrappedKeys[1] = "vault:v1:ct1";

        var ex = await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => HashiCorpVaultKeyProvider.CreateAsync(client.Object, opts));
        Assert.Contains("TransitKeyName", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateAsync_throws_when_ciphertext_is_whitespace()
    {
        var client = new Mock<IVaultTransitDecryptClient>();
        var opts = new HashiCorpVaultKeyProviderOptions { TransitKeyName = "orionvault", ActiveKeyId = 1 };
        opts.WrappedKeys[1] = "   ";

        await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => HashiCorpVaultKeyProvider.CreateAsync(client.Object, opts));
    }

    [Fact]
    public async Task CreateAsync_throws_when_decrypt_returns_zero_bytes()
    {
        var client = new Mock<IVaultTransitDecryptClient>();
        client.Setup(c => c.DecryptAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Array.Empty<byte>());

        var opts = new HashiCorpVaultKeyProviderOptions { TransitKeyName = "orionvault", ActiveKeyId = 1 };
        opts.WrappedKeys[1] = "vault:v1:ct1";

        await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => HashiCorpVaultKeyProvider.CreateAsync(client.Object, opts));
    }

    [Fact]
    public async Task CreateAsync_throws_when_decrypted_key_is_wrong_length()
    {
        var client = new Mock<IVaultTransitDecryptClient>();
        client.Setup(c => c.DecryptAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new byte[16]);

        var opts = new HashiCorpVaultKeyProviderOptions { TransitKeyName = "orionvault", ActiveKeyId = 1 };
        opts.WrappedKeys[1] = "vault:v1:ct1";

        var ex = await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => HashiCorpVaultKeyProvider.CreateAsync(client.Object, opts));
        Assert.Contains("32", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateAsync_surfaces_decrypt_client_failure()
    {
        var client = new Mock<IVaultTransitDecryptClient>();
        client.Setup(c => c.DecryptAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("vault permission denied"));

        var opts = new HashiCorpVaultKeyProviderOptions { TransitKeyName = "orionvault", ActiveKeyId = 1 };
        opts.WrappedKeys[1] = "vault:v1:ct1";

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => HashiCorpVaultKeyProvider.CreateAsync(client.Object, opts));
    }

    [Fact]
    public async Task CreateAsync_translates_revoked_transit_key_into_revocation_KeyUnwrapException()
    {
        var client = new Mock<IVaultTransitDecryptClient>();
        client.Setup(c => c.DecryptAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new VaultApiException(HttpStatusCode.Forbidden, "permission denied"));

        var opts = new HashiCorpVaultKeyProviderOptions { TransitKeyName = "orionvault", ActiveKeyId = 1 };
        opts.WrappedKeys[1] = "vault:v1:ct1";

        var ex = await Assert.ThrowsAsync<KeyUnwrapException>(
            () => HashiCorpVaultKeyProvider.CreateAsync(client.Object, opts));
        Assert.Equal(KeyUnwrapFailureKind.Revocation, ex.Kind);
        Assert.Contains("key id 1", ex.Message, StringComparison.Ordinal);
    }

    // ---- classification ----

    [Theory]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.NotFound)]
    public void TryClassify_maps_revocation_class_statuses_to_Revocation(HttpStatusCode status)
    {
        var classified = HashiCorpVaultKeyProvider.TryClassify(new VaultApiException(status, "denied"));
        Assert.NotNull(classified);
        Assert.Equal(KeyUnwrapFailureKind.Revocation, classified!.Kind);
    }

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.PreconditionFailed)]
    public void TryClassify_maps_other_statuses_to_Transient(HttpStatusCode status)
    {
        var classified = HashiCorpVaultKeyProvider.TryClassify(new VaultApiException(status, "blip"));
        Assert.NotNull(classified);
        Assert.Equal(KeyUnwrapFailureKind.Transient, classified!.Kind);
    }

    [Fact]
    public void TryClassify_returns_null_for_non_vault_exception()
        => Assert.Null(HashiCorpVaultKeyProvider.TryClassify(new InvalidOperationException("not vault")));

    // ---- cache-source seam ----

    [Fact]
    public void CreateUnwrappedKeySource_null_guards_its_arguments()
    {
        var opts = new HashiCorpVaultKeyProviderOptions { TransitKeyName = "orionvault", ActiveKeyId = 1 };
        Assert.Throws<ArgumentNullException>(
            () => HashiCorpVaultKeyProvider.CreateUnwrappedKeySource(null!, opts));
        Assert.Throws<ArgumentNullException>(
            () => HashiCorpVaultKeyProvider.CreateUnwrappedKeySource(Mock.Of<IVaultTransitDecryptClient>(), null!));
    }

    [Fact]
    public void Cache_fails_closed_when_refresh_hits_a_revoked_transit_key_even_with_serve_stale()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var client = new Mock<IVaultTransitDecryptClient>();
        var calls = 0;
        client.Setup(c => c.DecryptAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(() =>
            {
                var call = Interlocked.Increment(ref calls);
                return call == 1
                    ? Task.FromResult(Key32(0x11))
                    : Task.FromException<byte[]>(new VaultApiException(HttpStatusCode.Forbidden, "revoked"));
            });

        var opts = new HashiCorpVaultKeyProviderOptions { TransitKeyName = "orionvault", ActiveKeyId = 1 };
        opts.WrappedKeys[1] = "vault:v1:ct1";

        var source = HashiCorpVaultKeyProvider.CreateUnwrappedKeySource(client.Object, opts);
        using var cache = new CachingKeyProvider(
            source,
            new EnvelopeKeyCacheOptions { Enabled = true, Ttl = TimeSpan.FromMinutes(15), ServeStaleOnRefreshFailure = true },
            time);

        Assert.NotNull(cache.TryGetKey(1)); // prime ok
        time.Advance(TimeSpan.FromMinutes(20));

        var ex = Assert.Throws<KeyUnwrapException>(() => cache.TryGetKey(1));
        Assert.Equal(KeyUnwrapFailureKind.Revocation, ex.Kind);
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset now;

        public ManualTimeProvider(DateTimeOffset start) => now = start;

        public override DateTimeOffset GetUtcNow() => now;

        public void Advance(TimeSpan by) => now += by;
    }
}
