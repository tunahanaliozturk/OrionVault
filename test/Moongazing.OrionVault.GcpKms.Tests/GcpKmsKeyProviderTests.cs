namespace Moongazing.OrionVault.GcpKms.Tests;

using System.Text;
using Grpc.Core;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Caching;
using Moongazing.OrionVault.Exceptions;
using Moongazing.OrionVault.GcpKms;
using Moq;
using Xunit;

public sealed class GcpKmsKeyProviderTests
{
    private const string KeyName = "projects/p/locations/global/keyRings/r/cryptoKeys/k";

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
            () => new GcpKmsKeyProvider(activeKeyId: 7, plaintextKeys: keys));
    }

    [Fact]
    public void Constructor_throws_when_any_key_is_not_32_bytes()
    {
        var keys = new Dictionary<short, ReadOnlyMemory<byte>>
        {
            [1] = new byte[16],
        };

        var ex = Assert.Throws<OrionVaultConfigurationException>(
            () => new GcpKmsKeyProvider(activeKeyId: 1, plaintextKeys: keys));
        Assert.Contains("32", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TryGetKey_returns_registered_key_and_null_for_unknown()
    {
        var keyOne = Key32(0x11);
        var sut = new GcpKmsKeyProvider(activeKeyId: 1, new Dictionary<short, ReadOnlyMemory<byte>>
        {
            [1] = keyOne,
        });

        Assert.Equal(1, sut.ActiveKeyId);
        Assert.Equal(1, sut.KeyCount);
        Assert.True(keyOne.AsSpan().SequenceEqual(sut.TryGetKey(1)!.Value.Span));
        Assert.Null(sut.TryGetKey(99));
    }

    [Fact]
    public async Task CreateAsync_decrypts_each_configured_blob_via_decrypt_client()
    {
        var client = new Mock<IGcpKmsDecryptClient>();
        var key1 = Key32(0x11);
        var key2 = Key32(0x22);
        client.Setup(c => c.DecryptAsync(KeyName, It.Is<byte[]>(b => Encoding.ASCII.GetString(b) == "ct1"), It.IsAny<CancellationToken>()))
            .ReturnsAsync(key1);
        client.Setup(c => c.DecryptAsync(KeyName, It.Is<byte[]>(b => Encoding.ASCII.GetString(b) == "ct2"), It.IsAny<CancellationToken>()))
            .ReturnsAsync(key2);

        var opts = new GcpKmsKeyProviderOptions
        {
            CryptoKeyName = KeyName,
            ActiveKeyId = 1,
        };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));
        opts.WrappedKeys[2] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct2"));

        var sut = await GcpKmsKeyProvider.CreateAsync(client.Object, opts);

        Assert.Equal(1, sut.ActiveKeyId);
        Assert.True(key1.AsSpan().SequenceEqual(sut.TryGetKey(1)!.Value.Span));
        Assert.True(key2.AsSpan().SequenceEqual(sut.TryGetKey(2)!.Value.Span));
        client.Verify(c => c.DecryptAsync(It.IsAny<string>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    [Fact]
    public async Task CreateAsync_passes_configured_crypto_key_name_to_every_decrypt()
    {
        // The provider validated CryptoKeyName must be the exact name handed to the Decrypt call.
        var client = new Mock<IGcpKmsDecryptClient>();
        client.Setup(c => c.DecryptAsync(It.IsAny<string>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Key32(0x11));

        var opts = new GcpKmsKeyProviderOptions { CryptoKeyName = KeyName, ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));
        opts.WrappedKeys[2] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct2"));

        await GcpKmsKeyProvider.CreateAsync(client.Object, opts);

        // Both decrypts must carry the configured name; none under any other name.
        client.Verify(
            c => c.DecryptAsync(KeyName, It.IsAny<byte[]>(), It.IsAny<CancellationToken>()),
            Times.Exactly(2));
        client.Verify(
            c => c.DecryptAsync(It.Is<string>(n => n != KeyName), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task CreateAsync_throws_when_WrappedKeys_is_empty()
    {
        var client = new Mock<IGcpKmsDecryptClient>();
        var opts = new GcpKmsKeyProviderOptions
        {
            CryptoKeyName = KeyName,
            ActiveKeyId = 1,
        };

        await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => GcpKmsKeyProvider.CreateAsync(client.Object, opts));
    }

    [Fact]
    public async Task CreateAsync_throws_when_CryptoKeyName_is_blank()
    {
        var client = new Mock<IGcpKmsDecryptClient>();
        var opts = new GcpKmsKeyProviderOptions { CryptoKeyName = "  ", ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(new byte[] { 1, 2, 3 });

        var ex = await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => GcpKmsKeyProvider.CreateAsync(client.Object, opts));
        Assert.Contains("CryptoKeyName", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateAsync_throws_when_ciphertext_is_not_base64()
    {
        var client = new Mock<IGcpKmsDecryptClient>();
        var opts = new GcpKmsKeyProviderOptions
        {
            CryptoKeyName = KeyName,
            ActiveKeyId = 1,
        };
        opts.WrappedKeys[1] = "not-base64-!!";

        var ex = await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => GcpKmsKeyProvider.CreateAsync(client.Object, opts));
        Assert.Contains("base64", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateAsync_throws_when_ciphertext_is_whitespace()
    {
        var client = new Mock<IGcpKmsDecryptClient>();
        var opts = new GcpKmsKeyProviderOptions
        {
            CryptoKeyName = KeyName,
            ActiveKeyId = 1,
        };
        opts.WrappedKeys[1] = "   ";

        await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => GcpKmsKeyProvider.CreateAsync(client.Object, opts));
    }

    [Fact]
    public async Task CreateAsync_throws_when_decoded_ciphertext_is_zero_bytes()
    {
        var client = new Mock<IGcpKmsDecryptClient>();
        var opts = new GcpKmsKeyProviderOptions
        {
            CryptoKeyName = KeyName,
            ActiveKeyId = 1,
        };
        opts.WrappedKeys[1] = Convert.ToBase64String(Array.Empty<byte>());

        await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => GcpKmsKeyProvider.CreateAsync(client.Object, opts));
    }

    [Fact]
    public async Task CreateAsync_surfaces_decrypt_client_failure()
    {
        var client = new Mock<IGcpKmsDecryptClient>();
        client.Setup(c => c.DecryptAsync(It.IsAny<string>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("KMS permission denied"));

        var opts = new GcpKmsKeyProviderOptions
        {
            CryptoKeyName = KeyName,
            ActiveKeyId = 1,
        };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => GcpKmsKeyProvider.CreateAsync(client.Object, opts));
    }

    // ---- envelope-key cache adapter: classification + reload-aware refresh ----

    [Fact]
    public void CreateUnwrappedKeySource_null_guards_its_arguments()
    {
        var opts = new GcpKmsKeyProviderOptions { CryptoKeyName = KeyName, ActiveKeyId = 1 };
        Assert.Throws<ArgumentNullException>(
            () => GcpKmsKeyProvider.CreateUnwrappedKeySource(null!, opts));
        Assert.Throws<ArgumentNullException>(
            () => GcpKmsKeyProvider.CreateUnwrappedKeySource(Mock.Of<IGcpKmsDecryptClient>(), null!));
    }

    [Theory]
    [InlineData(StatusCode.PermissionDenied)]
    [InlineData(StatusCode.Unauthenticated)]
    [InlineData(StatusCode.NotFound)]
    [InlineData(StatusCode.FailedPrecondition)]
    [InlineData(StatusCode.InvalidArgument)]
    public void TryClassify_maps_revocation_class_statuses_to_Revocation(StatusCode code)
    {
        var classified = GcpKmsKeyProvider.TryClassify(new RpcException(new Status(code, "denied")));
        Assert.NotNull(classified);
        Assert.Equal(KeyUnwrapFailureKind.Revocation, classified!.Kind);
    }

    [Theory]
    [InlineData(StatusCode.Unavailable)]
    [InlineData(StatusCode.DeadlineExceeded)]
    [InlineData(StatusCode.ResourceExhausted)]
    [InlineData(StatusCode.Internal)]
    public void TryClassify_maps_other_statuses_to_Transient(StatusCode code)
    {
        var classified = GcpKmsKeyProvider.TryClassify(new RpcException(new Status(code, "blip")));
        Assert.NotNull(classified);
        Assert.Equal(KeyUnwrapFailureKind.Transient, classified!.Kind);
    }

    [Fact]
    public void TryClassify_returns_null_for_non_rpc_exception()
        => Assert.Null(GcpKmsKeyProvider.TryClassify(new InvalidOperationException("not gRPC")));

    [Fact]
    public void Cache_refresh_re_runs_kms_decrypt_and_picks_up_rotated_key()
    {
        // A reload-aware refresh: after the TTL elapses the adapter re-runs DecryptAsync, so a
        // KMS-side rotation (different plaintext for the same ciphertext) is honoured.
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var decryptCalls = 0;
        var fake = new FakeDecryptClient((_, _) =>
        {
            var call = Interlocked.Increment(ref decryptCalls);
            return call == 1 ? Key32(0x11) : Key32(0x22);
        });

        var opts = new GcpKmsKeyProviderOptions { CryptoKeyName = KeyName, ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));

        var source = GcpKmsKeyProvider.CreateUnwrappedKeySource(fake, opts);
        using var cache = new CachingKeyProvider(source, CacheOpts(TimeSpan.FromMinutes(15)), time);

        Assert.True(Key32(0x11).AsSpan().SequenceEqual(cache.TryGetKey(1)!.Value.Span));
        Assert.Equal(1, decryptCalls);

        time.Advance(TimeSpan.FromMinutes(15));

        Assert.True(Key32(0x22).AsSpan().SequenceEqual(cache.TryGetKey(1)!.Value.Span));
        Assert.Equal(2, decryptCalls); // the refresh actually re-decrypted
    }

    [Fact]
    public void Cache_fails_closed_when_refresh_hits_a_revoked_key_even_with_serve_stale()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var calls = 0;
        var fake = new FakeDecryptClient((_, _) =>
        {
            var call = Interlocked.Increment(ref calls);
            if (call == 1)
            {
                return Key32(0x11);
            }
            throw new RpcException(new Status(StatusCode.PermissionDenied, "key revoked"));
        });

        var opts = new GcpKmsKeyProviderOptions { CryptoKeyName = KeyName, ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));

        var source = GcpKmsKeyProvider.CreateUnwrappedKeySource(fake, opts);
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
        var fake = new FakeDecryptClient((_, _) =>
        {
            var call = Interlocked.Increment(ref calls);
            if (call == 1)
            {
                return Key32(0x11);
            }
            throw new RpcException(new Status(StatusCode.Unavailable, "kms unreachable"));
        });

        var opts = new GcpKmsKeyProviderOptions { CryptoKeyName = KeyName, ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));

        var source = GcpKmsKeyProvider.CreateUnwrappedKeySource(fake, opts);
        using var cache = new CachingKeyProvider(source, CacheOpts(TimeSpan.FromMinutes(15), serveStale: true), time);

        Assert.True(Key32(0x11).AsSpan().SequenceEqual(cache.TryGetKey(1)!.Value.Span));
        time.Advance(TimeSpan.FromMinutes(20));

        // Transient fault with serve-stale: last-good key keeps decrypting.
        Assert.True(Key32(0x11).AsSpan().SequenceEqual(cache.TryGetKey(1)!.Value.Span));
        Assert.True(calls >= 2);
    }

    private static EnvelopeKeyCacheOptions CacheOpts(TimeSpan ttl, bool serveStale = true)
        => new() { Enabled = true, Ttl = ttl, ServeStaleOnRefreshFailure = serveStale };

    private sealed class FakeDecryptClient : IGcpKmsDecryptClient
    {
        private readonly Func<string, byte[], byte[]> decrypt;

        public FakeDecryptClient(Func<string, byte[], byte[]> decrypt) => this.decrypt = decrypt;

        // The provider awaits this; a synchronous throw from the func surfaces as a faulted task
        // exactly as a real gRPC fault would, without a broad catch in the seam.
        public Task<byte[]> DecryptAsync(string cryptoKeyName, byte[] ciphertext, CancellationToken cancellationToken)
            => Task.FromResult(decrypt(cryptoKeyName, ciphertext));
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset now;

        public ManualTimeProvider(DateTimeOffset start) => now = start;

        public override DateTimeOffset GetUtcNow() => now;

        public void Advance(TimeSpan by) => now += by;
    }
}
