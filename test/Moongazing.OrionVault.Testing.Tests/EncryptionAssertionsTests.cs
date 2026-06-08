namespace Moongazing.OrionVault.Testing.Tests;

using System.Text;
using Moongazing.OrionVault.Testing;
using Xunit;

public sealed class EncryptionAssertionsTests
{
    private static byte[] BuildCiphertext(short keyId)
    {
        // Header (2 bytes key id + 12 byte nonce) + 16 byte tag = 30 bytes minimum.
        // CipherFormat reads the key id as big-endian, so the high byte goes first.
        var bytes = new byte[30];
        bytes[0] = (byte)((keyId >> 8) & 0xFF);
        bytes[1] = (byte)(keyId & 0xFF);
        return bytes;
    }

    [Fact]
    public void IsEncrypted_passes_on_minimum_length_payload()
    {
        EncryptionAssertions.IsEncrypted(BuildCiphertext(1));
    }

    [Fact]
    public void IsEncrypted_throws_on_too_short_payload()
    {
        var ex = Assert.Throws<Xunit.Sdk.XunitException>(
            () => EncryptionAssertions.IsEncrypted(new byte[5]));
        Assert.Contains("Expected encrypted column", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void IsNotEncrypted_passes_on_plaintext_short_bytes()
    {
        // Plaintext "hello" - 5 UTF-8 bytes, well below the 30-byte ciphertext threshold.
        EncryptionAssertions.IsNotEncrypted(Encoding.UTF8.GetBytes("hello"));
    }

    [Fact]
    public void IsNotEncrypted_throws_on_ciphertext_shaped_bytes()
    {
        var ex = Assert.Throws<Xunit.Sdk.XunitException>(
            () => EncryptionAssertions.IsNotEncrypted(BuildCiphertext(1)));
        Assert.Contains("Expected plaintext column", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void IsEncryptedWithActiveKey_passes_when_key_id_matches()
    {
        var provider = new TestKeyProvider(activeKeyId: 7);
        provider.Add(7, new byte[32]);

        EncryptionAssertions.IsEncryptedWithActiveKey(BuildCiphertext(7), provider);
    }

    [Fact]
    public void IsEncryptedWithActiveKey_throws_when_key_id_mismatches()
    {
        var provider = new TestKeyProvider(activeKeyId: 7);
        provider.Add(7, new byte[32]);

        var ex = Assert.Throws<Xunit.Sdk.XunitException>(
            () => EncryptionAssertions.IsEncryptedWithActiveKey(BuildCiphertext(5), provider));
        Assert.Contains("key id 7", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DoesNotContainPlaintext_passes_when_value_is_not_present()
    {
        EncryptionAssertions.DoesNotContainPlaintext(
            Encoding.UTF8.GetBytes("ciphertext-only"),
            "secret123");
    }

    [Fact]
    public void DoesNotContainPlaintext_throws_when_value_appears_in_bytes()
    {
        var bytes = Encoding.UTF8.GetBytes("prefix-secret123-suffix");
        var ex = Assert.Throws<Xunit.Sdk.XunitException>(
            () => EncryptionAssertions.DoesNotContainPlaintext(bytes, "secret123"));
        Assert.Contains("'secret123'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DoesNotContainPlaintext_passes_when_bytes_are_not_valid_utf8()
    {
        // Random binary that fails UTF-8 decode - decode returns null and assertion passes
        // (we cannot find a plaintext in undecodable bytes).
        var bytes = new byte[] { 0xFF, 0xFE, 0xFD, 0xFC };
        EncryptionAssertions.DoesNotContainPlaintext(bytes, "anything");
    }
}
