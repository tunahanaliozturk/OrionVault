namespace Moongazing.OrionVault.Testing;

using System.Diagnostics.CodeAnalysis;
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
    /// Asserts <paramref name="columnValue"/> is NOT encrypted under any key registered with
    /// the supplied <paramref name="encryptor"/> by attempting a real decrypt and asserting
    /// it fails. Distinct from the dropped v0.2.1 length-only heuristic: a long plaintext
    /// column that happens to be larger than <c>CipherFormat.MinimumCiphertextLength</c> now
    /// classifies correctly because the decrypt fails on auth tag verification.
    /// </summary>
    /// <remarks>
    /// Pairs with <c>RemovedEncryptedAttribute</c>-style regression tests: confirm that after
    /// removing <c>[Encrypted]</c> from a property, the column on disk is plaintext rather
    /// than ciphertext under a previously-active key. The implementation tolerates the
    /// fast-path (column shorter than the minimum ciphertext layout) by returning early.
    /// <para>
    /// IMPORTANT: pass the <see cref="IEncryptor"/> registered by <c>AddOrionVault(...)</c>
    /// (real AES-GCM crypto). Do NOT use the <c>PlaintextEncryptor</c> stub from the testing
    /// package: that stub is a no-op designed for ciphertext-layout inspection and returns
    /// success for any input shaped like a ciphertext header, which would re-introduce the
    /// length-based false positive this overload was specifically designed to eliminate.
    /// </para>
    /// </remarks>
    public static void IsNotEncrypted(byte[] columnValue, IEncryptor encryptor)
    {
        ArgumentNullException.ThrowIfNull(columnValue);
        ArgumentNullException.ThrowIfNull(encryptor);

        // Too short to even carry the OrionVault header: definitely not encrypted.
        if (columnValue.Length < CipherFormat.MinimumCiphertextLength)
        {
            return;
        }

        // Attempt a decrypt. If it succeeds, the bytes are valid OrionVault ciphertext under
        // a registered key and the assertion fails. If the decrypt throws (wrong header,
        // unknown key id, AES-GCM tag mismatch), the bytes are not OrionVault ciphertext.
        try
        {
            _ = encryptor.DecryptBytes(columnValue);
        }
#pragma warning disable CA1031 // we deliberately catch everything: any decrypt failure means "not ciphertext under any registered key"
        catch
#pragma warning restore CA1031
        {
            return;
        }

        throw new Xunit.Sdk.XunitException(
            "Expected plaintext column but decryptor returned a valid plaintext under a registered OrionVault key.");
    }

    /// <summary>
    /// Decodes <paramref name="columnValue"/> as strict UTF-8 (throws on invalid bytes) and
    /// asserts that the result does NOT contain <paramref name="expectedPlaintext"/>. Bytes
    /// that fail to decode as UTF-8 are treated as "definitely not the plaintext", which
    /// matches the intended ciphertext-bytes-on-disk scenario.
    /// </summary>
    /// <remarks>
    /// Use this for the "I just inserted a row with <c>'secret123'</c> as the value, prove it
    /// is not stored verbatim on disk" assertion when the consumer reads back the raw column
    /// via raw SQL. Pairs with the v0.2.0 background re-encryption service so consumer
    /// integration tests can demonstrate that re-encrypted rows do not leak plaintext via the
    /// previous key.
    /// </remarks>
    public static void DoesNotContainPlaintext(byte[] columnValue, string expectedPlaintext)
    {
        ArgumentNullException.ThrowIfNull(columnValue);
        ArgumentException.ThrowIfNullOrEmpty(expectedPlaintext);

        var decoded = TryDecodeStrictUtf8(columnValue);
        if (decoded is not null && decoded.Contains(expectedPlaintext, StringComparison.Ordinal))
        {
            throw new Xunit.Sdk.XunitException(
                $"Expected plaintext '{expectedPlaintext}' NOT to appear in the column bytes, but it did.");
        }
    }

    // System.Text.Encoding.UTF8 silently replaces invalid bytes with U+FFFD instead of
    // throwing - so a ciphertext byte run could decode to a noisy string containing a
    // false positive. Use a strict encoding that throws on the first invalid byte so
    // ciphertext input is reliably classified as "not utf-8 = does not contain plaintext".
    private static readonly Encoding StrictUtf8 = new UTF8Encoding(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private static string? TryDecodeStrictUtf8(byte[] bytes)
    {
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }
}
