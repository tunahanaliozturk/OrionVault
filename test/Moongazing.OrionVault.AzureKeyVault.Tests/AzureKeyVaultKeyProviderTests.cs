namespace Moongazing.OrionVault.AzureKeyVault.Tests;

using System.Text;
using Moongazing.OrionVault.AzureKeyVault;
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
}
