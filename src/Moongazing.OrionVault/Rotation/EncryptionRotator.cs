namespace Moongazing.OrionVault.Rotation;

using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Exceptions;
using Moongazing.OrionVault.Internal;

/// <summary>
/// Helper that re-encrypts a single ciphertext blob from its current key id to the
/// active key id of an <see cref="IEncryptor"/>. Used by consumers running a one-shot
/// rotation pass after rolling the <c>ActiveKeyId</c> on their <see cref="IKeyProvider"/>:
/// existing rows still carry the previous-active key id in their header, and a periodic
/// job uses <see cref="EncryptionRotator"/> to walk those rows and refresh them under
/// the new key.
/// </summary>
/// <remarks>
/// <para>
/// The rotator does NOT walk EF Core tables itself - consumers feed it a stream of
/// ciphertexts because the query shape depends on the table layout (which columns are
/// encrypted, which entity the column belongs to). The rotator just decrypts +
/// re-encrypts one blob at a time, returning the new ciphertext.
/// </para>
/// <para>
/// To avoid re-encrypting rows that are already on the active key (and burning AES
/// cycles for no reason), call <see cref="NeedsRotation"/> first - it reads the 2-byte
/// key id header without touching the IEncryptor and returns true only when the header
/// differs from the supplied active id.
/// </para>
/// </remarks>
public static class EncryptionRotator
{
    /// <summary>
    /// Return true when the supplied <paramref name="ciphertext"/> was encrypted under a
    /// key id different from <paramref name="activeKeyId"/>. Read-only - does NOT decrypt
    /// or invoke the encryptor.
    /// </summary>
    /// <exception cref="OrionVaultDecryptionException">
    /// <paramref name="ciphertext"/> is shorter than the shortest well-formed envelope
    /// (<c>[keyId:2 | nonce:12 | tag:16]</c> = 30 bytes), so it is not an envelope at all: a
    /// never-encrypted value left behind by a plaintext-to-encrypted migration, or a truncated
    /// blob. Such a value has no key id to answer about, and answering "false" would declare it
    /// already on the active key - which is how a rotation sweep ends up reporting a clean pass
    /// over a column that was never encrypted, as long as its first two bytes happened to match
    /// the active key id. Surfacing it lets the caller count the row as the failure it is, and it
    /// is the same exception decrypting the value would raise.
    /// </exception>
    public static bool NeedsRotation(byte[] ciphertext, short activeKeyId)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        if (ciphertext.Length < CipherFormat.MinimumCiphertextLength)
        {
            // Deliberately NOT "false": a two-byte length gate would let any short blob whose
            // first two bytes happen to equal the active key id pass as healthy. And deliberately
            // not re-encrypting it either - the value was never ciphertext, so encrypting it would
            // bury an unencrypted value under a key instead of reporting it.
            throw new OrionVaultDecryptionException(
                $"Ciphertext length {ciphertext.Length} is below the minimum {CipherFormat.MinimumCiphertextLength}; " +
                "the value is not an OrionVault envelope, so no key id can be read from it.");
        }
        // Header is [keyId:2 | nonce:12 | tag:16 | ciphertext:N]; CipherFormat writes
        // the key id big-endian (BinaryPrimitives.WriteInt16BigEndian) so we decode the
        // same way here.
        var header = System.Buffers.Binary.BinaryPrimitives.ReadInt16BigEndian(ciphertext);
        return header != activeKeyId;
    }

    /// <summary>
    /// Decrypt <paramref name="ciphertext"/> under whatever key id its header carries
    /// and re-encrypt under the supplied <paramref name="encryptor"/>'s active key id.
    /// The returned blob is a fresh ciphertext suitable for writing back to storage.
    /// </summary>
    public static byte[] Rotate(IEncryptor encryptor, byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(encryptor);
        ArgumentNullException.ThrowIfNull(ciphertext);
        var plaintext = encryptor.DecryptBytes(ciphertext);
        return encryptor.EncryptBytes(plaintext);
    }

    /// <summary>
    /// Convenience: decrypt + re-encrypt a UTF-8 string column.
    /// </summary>
    public static byte[] RotateString(IEncryptor encryptor, byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(encryptor);
        ArgumentNullException.ThrowIfNull(ciphertext);
        var plaintext = encryptor.DecryptString(ciphertext);
        return encryptor.EncryptString(plaintext);
    }
}
