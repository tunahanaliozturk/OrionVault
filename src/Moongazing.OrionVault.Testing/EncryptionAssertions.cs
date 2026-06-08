namespace Moongazing.OrionVault.Testing;

using System.Text;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Internal;

/// <summary>
/// Assertion helpers that inspect raw column bytes produced by OrionVault. Throws
/// <see cref="Xunit.Sdk.XunitException"/> so failures show up as regular xUnit assertion
/// failures.
/// </summary>
public static class EncryptionAssertions
{
    /// <summary>
    /// Asserts that <paramref name="columnValue"/> is an OrionVault-shaped ciphertext: at
    /// least <c>HeaderSize + TagSize</c> bytes long, so the key id, nonce, and tag are all
    /// representable. Does not attempt to decrypt - use the encryptor for that.
    /// </summary>
    public static void IsEncrypted(byte[] columnValue)
    {
        ArgumentNullException.ThrowIfNull(columnValue);
        if (columnValue.Length < CipherFormat.MinimumCiphertextLength)
        {
            throw new Xunit.Sdk.XunitException(
                $"Expected encrypted column (>= {CipherFormat.MinimumCiphertextLength} bytes), got {columnValue.Length} bytes.");
        }
    }

    /// <summary>Reads the key id from the OrionVault ciphertext header.</summary>
    public static short ReadKeyId(byte[] columnValue)
    {
        IsEncrypted(columnValue);
        return CipherFormat.ReadKeyId(columnValue);
    }

    /// <summary>Asserts the column is encrypted under <paramref name="expectedKeyId"/>.</summary>
    public static void IsEncryptedWithKey(byte[] columnValue, short expectedKeyId)
    {
        var actual = ReadKeyId(columnValue);
        if (actual != expectedKeyId)
        {
            throw new Xunit.Sdk.XunitException(
                $"Expected encrypted with key id {expectedKeyId}, got {actual}.");
        }
    }

    /// <summary>
    /// Asserts the column is encrypted under the <see cref="IKeyProvider.ActiveKeyId"/> of
    /// the supplied <paramref name="provider"/>. Useful for re-encryption rollout tests
    /// where you want to confirm a row has migrated to the current key after the background
    /// re-encryption service has run.
    /// </summary>
    public static void IsEncryptedWithActiveKey(byte[] columnValue, IKeyProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        IsEncryptedWithKey(columnValue, provider.ActiveKeyId);
    }

    /// <summary>
    /// Asserts that <paramref name="columnValue"/> is NOT encrypted (too short to carry the
    /// OrionVault header). Useful for regression tests that confirm a column that was
    /// previously encrypted is now plaintext after the <c>[Encrypted]</c> attribute or
    /// <c>IsEncrypted()</c> wiring has been removed.
    /// </summary>
    public static void IsNotEncrypted(byte[] columnValue)
    {
        ArgumentNullException.ThrowIfNull(columnValue);
        if (columnValue.Length >= CipherFormat.MinimumCiphertextLength)
        {
            throw new Xunit.Sdk.XunitException(
                $"Expected plaintext column (< {CipherFormat.MinimumCiphertextLength} bytes), got {columnValue.Length} bytes that match the OrionVault ciphertext shape.");
        }
    }

    /// <summary>
    /// Decodes <paramref name="columnValue"/> as a UTF-8 string and asserts that the result
    /// does NOT contain <paramref name="expectedPlaintext"/>. Useful for the "I just inserted
    /// a row with 'secret123' as the value, prove it is not stored verbatim on disk" assertion
    /// when the consumer reads back the raw column via raw SQL.
    /// </summary>
    public static void DoesNotContainPlaintext(byte[] columnValue, string expectedPlaintext)
    {
        ArgumentNullException.ThrowIfNull(columnValue);
        ArgumentException.ThrowIfNullOrEmpty(expectedPlaintext);

        var decoded = TryDecodeUtf8(columnValue);
        if (decoded is not null && decoded.Contains(expectedPlaintext, StringComparison.Ordinal))
        {
            throw new Xunit.Sdk.XunitException(
                $"Expected plaintext '{expectedPlaintext}' NOT to appear in the column bytes, but it did.");
        }
    }

    private static string? TryDecodeUtf8(byte[] bytes)
    {
        try
        {
            return Encoding.UTF8.GetString(bytes);
        }
#pragma warning disable CA1031 // decode failure means "not utf-8", which is exactly what we want for ciphertext
        catch
#pragma warning restore CA1031
        {
            return null;
        }
    }
}
