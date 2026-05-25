namespace Moongazing.OrionVault.Abstractions;

/// <summary>
/// Encrypts and decrypts column values. The on-disk layout is
/// <c>[keyId:2 | nonce:12 | tag:16 | ciphertext:N]</c> (30-byte fixed overhead).
/// Implementations must be thread-safe and registered as singletons.
/// </summary>
public interface IEncryptor
{
    /// <summary>
    /// Encrypts a UTF-8 string. Output is the standard layout above.
    /// </summary>
    byte[] EncryptString(string plaintext);

    /// <summary>
    /// Decrypts to a UTF-8 string. Reads the key id from the first 2 bytes
    /// of <paramref name="ciphertext"/>.
    /// </summary>
    /// <exception cref="Exceptions.OrionVaultDecryptionException">
    /// Thrown on tampering, malformed input, or unknown key id.
    /// </exception>
    string DecryptString(byte[] ciphertext);

    /// <summary>
    /// Encrypts a raw byte array. Output is the standard layout above.
    /// </summary>
    byte[] EncryptBytes(byte[] plaintext);

    /// <summary>
    /// Decrypts a raw byte array. Reads the key id from the first 2 bytes
    /// of <paramref name="ciphertext"/>.
    /// </summary>
    /// <exception cref="Exceptions.OrionVaultDecryptionException">
    /// Thrown on tampering, malformed input, or unknown key id.
    /// </exception>
    byte[] DecryptBytes(byte[] ciphertext);
}
