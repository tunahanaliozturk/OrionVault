namespace Moongazing.OrionVault.AwsKms.Tests;

using System.IO;
using System.Net;
using System.Text;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.AwsKms;
using Moongazing.OrionVault.Caching;
using Moongazing.OrionVault.Exceptions;
using Moq;
using Xunit;

public sealed class AwsKmsKeyProviderTests
{
    private const string Cmk = "arn:aws:kms:us-east-1:111122223333:key/abcd1234-ab12-cd34-ef56-abcdef123456";

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
            () => new AwsKmsKeyProvider(activeKeyId: 7, plaintextKeys: keys));
    }

    [Fact]
    public void Constructor_throws_when_any_key_is_not_32_bytes()
    {
        var keys = new Dictionary<short, ReadOnlyMemory<byte>>
        {
            [1] = new byte[16],
        };

        var ex = Assert.Throws<OrionVaultConfigurationException>(
            () => new AwsKmsKeyProvider(activeKeyId: 1, plaintextKeys: keys));
        Assert.Contains("32", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TryGetKey_returns_registered_key_and_null_for_unknown()
    {
        var keyOne = Key32(0x11);
        var sut = new AwsKmsKeyProvider(activeKeyId: 1, new Dictionary<short, ReadOnlyMemory<byte>>
        {
            [1] = keyOne,
        });

        Assert.Equal(1, sut.ActiveKeyId);
        Assert.True(keyOne.AsSpan().SequenceEqual(sut.TryGetKey(1)!.Value.Span));
        Assert.Null(sut.TryGetKey(99));
    }

    [Fact]
    public async Task CreateAsync_decrypts_each_configured_blob_via_kms_client()
    {
        var kms = new Mock<IAmazonKeyManagementService>();
        var key1 = Key32(0x11);
        var key2 = Key32(0x22);
        kms.Setup(x => x.DecryptAsync(It.Is<DecryptRequest>(r => ReadAsAscii(r.CiphertextBlob) == "ct1"), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DecryptResponse { Plaintext = new MemoryStream(key1) });
        kms.Setup(x => x.DecryptAsync(It.Is<DecryptRequest>(r => ReadAsAscii(r.CiphertextBlob) == "ct2"), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DecryptResponse { Plaintext = new MemoryStream(key2) });

        var opts = new AwsKmsKeyProviderOptions { KeyId = Cmk, ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));
        opts.WrappedKeys[2] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct2"));

        var sut = await AwsKmsKeyProvider.CreateAsync(kms.Object, opts);

        Assert.Equal(1, sut.ActiveKeyId);
        Assert.True(key1.AsSpan().SequenceEqual(sut.TryGetKey(1)!.Value.Span));
        Assert.True(key2.AsSpan().SequenceEqual(sut.TryGetKey(2)!.Value.Span));
        kms.Verify(x => x.DecryptAsync(It.IsAny<DecryptRequest>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    [Fact]
    public async Task CreateAsync_pins_every_decrypt_to_the_configured_CMK()
    {
        // Without DecryptRequest.KeyId, KMS resolves the key from the ciphertext blob itself, so a
        // blob substituted into WrappedKeys decrypts under whatever CMK wrapped it. Every request
        // must carry the configured CMK.
        var kms = new Mock<IAmazonKeyManagementService>();
        kms.Setup(x => x.DecryptAsync(It.IsAny<DecryptRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DecryptResponse { Plaintext = new MemoryStream(Key32(0x11)) });

        var opts = new AwsKmsKeyProviderOptions { KeyId = Cmk, ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));
        opts.WrappedKeys[2] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct2"));

        await AwsKmsKeyProvider.CreateAsync(kms.Object, opts);

        kms.Verify(
            x => x.DecryptAsync(It.Is<DecryptRequest>(r => r.KeyId == Cmk), It.IsAny<CancellationToken>()),
            Times.Exactly(2));
        kms.Verify(
            x => x.DecryptAsync(It.Is<DecryptRequest>(r => string.IsNullOrEmpty(r.KeyId)), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task CreateAsync_throws_when_KeyId_is_missing()
    {
        var kms = new Mock<IAmazonKeyManagementService>();
        var opts = new AwsKmsKeyProviderOptions { ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));

        var ex = await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => AwsKmsKeyProvider.CreateAsync(kms.Object, opts));
        Assert.Contains("KeyId", ex.Message, StringComparison.Ordinal);
        kms.Verify(x => x.DecryptAsync(It.IsAny<DecryptRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task CreateAsync_throws_when_KeyId_is_whitespace()
    {
        var kms = new Mock<IAmazonKeyManagementService>();
        var opts = new AwsKmsKeyProviderOptions { KeyId = "   ", ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));

        var ex = await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => AwsKmsKeyProvider.CreateAsync(kms.Object, opts));
        Assert.Contains("KeyId", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateAsync_throws_when_WrappedKeys_is_empty()
    {
        var kms = new Mock<IAmazonKeyManagementService>();
        var opts = new AwsKmsKeyProviderOptions { KeyId = Cmk, ActiveKeyId = 1 };

        await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => AwsKmsKeyProvider.CreateAsync(kms.Object, opts));
    }

    [Fact]
    public async Task CreateAsync_throws_when_ciphertext_is_not_base64()
    {
        var kms = new Mock<IAmazonKeyManagementService>();
        var opts = new AwsKmsKeyProviderOptions { KeyId = Cmk, ActiveKeyId = 1 };
        opts.WrappedKeys[1] = "not-base64-!!";

        var ex = await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => AwsKmsKeyProvider.CreateAsync(kms.Object, opts));
        Assert.Contains("base64", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateAsync_throws_when_ciphertext_is_whitespace()
    {
        var kms = new Mock<IAmazonKeyManagementService>();
        var opts = new AwsKmsKeyProviderOptions { KeyId = Cmk, ActiveKeyId = 1 };
        opts.WrappedKeys[1] = "   ";

        await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => AwsKmsKeyProvider.CreateAsync(kms.Object, opts));
    }

    [Fact]
    public async Task CreateAsync_throws_when_decoded_ciphertext_is_zero_bytes()
    {
        var kms = new Mock<IAmazonKeyManagementService>();
        var opts = new AwsKmsKeyProviderOptions { KeyId = Cmk, ActiveKeyId = 1 };
        // Empty-string base64 decodes to zero bytes, so the KMS call would fail; we reject
        // it deterministically at startup before invoking the SDK.
        opts.WrappedKeys[1] = Convert.ToBase64String(Array.Empty<byte>());

        await Assert.ThrowsAsync<OrionVaultConfigurationException>(
            () => AwsKmsKeyProvider.CreateAsync(kms.Object, opts));
    }

    // ---- envelope-key cache adapter: classification + reload-aware refresh ----

    [Fact]
    public void CreateUnwrappedKeySource_null_guards_its_arguments()
    {
        var opts = new AwsKmsKeyProviderOptions { KeyId = Cmk, ActiveKeyId = 1 };
        Assert.Throws<ArgumentNullException>(
            () => AwsKmsKeyProvider.CreateUnwrappedKeySource(null!, opts));
        Assert.Throws<ArgumentNullException>(
            () => AwsKmsKeyProvider.CreateUnwrappedKeySource(Mock.Of<IAmazonKeyManagementService>(), null!));
    }

    public static TheoryData<Exception> RevocationFaults() => new()
    {
        new KMSInvalidStateException("key is disabled or pending deletion"),
        new DisabledException("key disabled"),
        new NotFoundException("key not found"),
        new InvalidCiphertextException("blob not decryptable under this key"),
        new IncorrectKeyException("wrong key for this ciphertext"),
        new AmazonKeyManagementServiceException("access denied") { ErrorCode = "AccessDeniedException" },
        new AmazonKeyManagementServiceException("forbidden") { StatusCode = HttpStatusCode.Forbidden },
    };

    [Theory]
    [MemberData(nameof(RevocationFaults))]
    public void TryClassify_maps_revocation_class_faults_to_Revocation(Exception fault)
    {
        var classified = AwsKmsKeyProvider.TryClassify(fault);
        Assert.NotNull(classified);
        Assert.Equal(KeyUnwrapFailureKind.Revocation, classified!.Kind);
    }

    public static TheoryData<Exception> TransientFaults() => new()
    {
        new LimitExceededException("throttled"),
        new KMSInternalException("kms internal error"),
        new DependencyTimeoutException("dependency timeout"),
        new AmazonKeyManagementServiceException("too many requests") { StatusCode = HttpStatusCode.TooManyRequests },
        new AmazonKeyManagementServiceException("service unavailable") { StatusCode = HttpStatusCode.ServiceUnavailable },
        new AmazonKeyManagementServiceException("bad gateway") { StatusCode = HttpStatusCode.BadGateway },
    };

    [Theory]
    [MemberData(nameof(TransientFaults))]
    public void TryClassify_maps_other_faults_to_Transient(Exception fault)
    {
        var classified = AwsKmsKeyProvider.TryClassify(fault);
        Assert.NotNull(classified);
        Assert.Equal(KeyUnwrapFailureKind.Transient, classified!.Kind);
    }

    [Fact]
    public void TryClassify_returns_null_for_non_aws_exception()
        => Assert.Null(AwsKmsKeyProvider.TryClassify(new InvalidOperationException("not AWS")));

    [Fact]
    public void Cache_refresh_re_runs_kms_decrypt_and_picks_up_rotated_key()
    {
        // A reload-aware refresh: after the TTL elapses the adapter re-runs DecryptAsync, so a
        // KMS-side rotation (different plaintext for the same ciphertext) is honoured.
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var decryptCalls = 0;
        var kms = FakeKms(() =>
        {
            var call = Interlocked.Increment(ref decryptCalls);
            return call == 1 ? Key32(0x11) : Key32(0x22);
        });

        var opts = new AwsKmsKeyProviderOptions { KeyId = Cmk, ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));

        var source = AwsKmsKeyProvider.CreateUnwrappedKeySource(kms, opts);
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
        // The incident-response case: the operator disables the CMK. Without this seam the
        // unwrap-once provider keeps the plaintext key for the whole process lifetime and the
        // revoked key goes on encrypting and decrypting until someone restarts the host.
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var calls = 0;
        var kms = FakeKms(() =>
        {
            var call = Interlocked.Increment(ref calls);
            if (call == 1)
            {
                return Key32(0x11);
            }
            throw new KMSInvalidStateException("key disabled");
        });

        var opts = new AwsKmsKeyProviderOptions { KeyId = Cmk, ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));

        var source = AwsKmsKeyProvider.CreateUnwrappedKeySource(kms, opts);
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
        var kms = FakeKms(() =>
        {
            var call = Interlocked.Increment(ref calls);
            if (call == 1)
            {
                return Key32(0x11);
            }
            throw new KMSInternalException("kms unreachable");
        });

        var opts = new AwsKmsKeyProviderOptions { KeyId = Cmk, ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));

        var source = AwsKmsKeyProvider.CreateUnwrappedKeySource(kms, opts);
        using var cache = new CachingKeyProvider(source, CacheOpts(TimeSpan.FromMinutes(15), serveStale: true), time);

        Assert.True(Key32(0x11).AsSpan().SequenceEqual(cache.TryGetKey(1)!.Value.Span));
        time.Advance(TimeSpan.FromMinutes(20));

        // Transient fault with serve-stale: last-good key keeps decrypting.
        Assert.True(Key32(0x11).AsSpan().SequenceEqual(cache.TryGetKey(1)!.Value.Span));
        Assert.True(calls >= 2);
    }

    [Fact]
    public void Cache_refresh_also_pins_the_configured_CMK()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var kms = new Mock<IAmazonKeyManagementService>();
        kms.Setup(x => x.DecryptAsync(It.IsAny<DecryptRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => new DecryptResponse { Plaintext = new MemoryStream(Key32(0x11)) });

        var opts = new AwsKmsKeyProviderOptions { KeyId = Cmk, ActiveKeyId = 1 };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));

        var source = AwsKmsKeyProvider.CreateUnwrappedKeySource(kms.Object, opts);
        using var cache = new CachingKeyProvider(source, CacheOpts(TimeSpan.FromMinutes(15)), time);

        Assert.NotNull(cache.TryGetKey(1));
        time.Advance(TimeSpan.FromMinutes(20));
        Assert.NotNull(cache.TryGetKey(1));

        kms.Verify(
            x => x.DecryptAsync(It.Is<DecryptRequest>(r => r.KeyId == Cmk), It.IsAny<CancellationToken>()),
            Times.Exactly(2));
    }

    private static EnvelopeKeyCacheOptions CacheOpts(TimeSpan ttl, bool serveStale = true)
        => new() { Enabled = true, Ttl = ttl, ServeStaleOnRefreshFailure = serveStale };

    // A synchronous throw from the func surfaces as a faulted task exactly as a real SDK fault
    // would, without a broad catch in the seam.
    private static IAmazonKeyManagementService FakeKms(Func<byte[]> decrypt)
    {
        var kms = new Mock<IAmazonKeyManagementService>();
        kms.Setup(x => x.DecryptAsync(It.IsAny<DecryptRequest>(), It.IsAny<CancellationToken>()))
            .Returns((DecryptRequest _, CancellationToken _) =>
                Task.FromResult(new DecryptResponse { Plaintext = new MemoryStream(decrypt()) }));
        return kms.Object;
    }

    private static string ReadAsAscii(Stream stream)
    {
        if (stream is MemoryStream ms)
        {
            return Encoding.ASCII.GetString(ms.ToArray());
        }
        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return Encoding.ASCII.GetString(copy.ToArray());
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset now;

        public ManualTimeProvider(DateTimeOffset start) => now = start;

        public override DateTimeOffset GetUtcNow() => now;

        public void Advance(TimeSpan by) => now = now.Add(by);
    }
}
