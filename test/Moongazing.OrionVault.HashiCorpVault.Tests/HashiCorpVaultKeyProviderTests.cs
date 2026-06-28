namespace Moongazing.OrionVault.HashiCorpVault.Tests;

using Moongazing.OrionVault.Exceptions;
using Moongazing.OrionVault.HashiCorpVault;
using Moq;
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
}
