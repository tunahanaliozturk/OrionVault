namespace Moongazing.OrionVault.GcpKms.Tests;

using System.Text;
using Moongazing.OrionVault.Exceptions;
using Moongazing.OrionVault.GcpKms;
using Moq;
using Xunit;

public sealed class GcpKmsKeyProviderTests
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
        client.Setup(c => c.DecryptAsync(It.Is<byte[]>(b => Encoding.ASCII.GetString(b) == "ct1"), It.IsAny<CancellationToken>()))
            .ReturnsAsync(key1);
        client.Setup(c => c.DecryptAsync(It.Is<byte[]>(b => Encoding.ASCII.GetString(b) == "ct2"), It.IsAny<CancellationToken>()))
            .ReturnsAsync(key2);

        var opts = new GcpKmsKeyProviderOptions
        {
            CryptoKeyName = "projects/p/locations/global/keyRings/r/cryptoKeys/k",
            ActiveKeyId = 1,
        };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));
        opts.WrappedKeys[2] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct2"));

        var sut = await GcpKmsKeyProvider.CreateAsync(client.Object, opts);

        Assert.Equal(1, sut.ActiveKeyId);
        Assert.True(key1.AsSpan().SequenceEqual(sut.TryGetKey(1)!.Value.Span));
        Assert.True(key2.AsSpan().SequenceEqual(sut.TryGetKey(2)!.Value.Span));
        client.Verify(c => c.DecryptAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    [Fact]
    public async Task CreateAsync_throws_when_WrappedKeys_is_empty()
    {
        var client = new Mock<IGcpKmsDecryptClient>();
        var opts = new GcpKmsKeyProviderOptions
        {
            CryptoKeyName = "projects/p/locations/global/keyRings/r/cryptoKeys/k",
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
            CryptoKeyName = "projects/p/locations/global/keyRings/r/cryptoKeys/k",
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
            CryptoKeyName = "projects/p/locations/global/keyRings/r/cryptoKeys/k",
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
            CryptoKeyName = "projects/p/locations/global/keyRings/r/cryptoKeys/k",
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
        client.Setup(c => c.DecryptAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("KMS permission denied"));

        var opts = new GcpKmsKeyProviderOptions
        {
            CryptoKeyName = "projects/p/locations/global/keyRings/r/cryptoKeys/k",
            ActiveKeyId = 1,
        };
        opts.WrappedKeys[1] = Convert.ToBase64String(Encoding.ASCII.GetBytes("ct1"));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => GcpKmsKeyProvider.CreateAsync(client.Object, opts));
    }
}
