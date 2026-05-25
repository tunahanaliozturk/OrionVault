namespace Moongazing.OrionVault.Testing;

using System.Text;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Internal;

/// <summary>
/// Drop-in <see cref="IEncryptor"/> that writes the standard 30-byte header
/// followed by the identity body (no actual encryption). The auth tag region
/// is zeros. Use only in tests that need to inspect ciphertext layout without
/// running real crypto.
/// </summary>
public sealed class PlaintextEncryptor : IEncryptor
{
    public byte[] EncryptString(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return EncryptBytes(Encoding.UTF8.GetBytes(plaintext));
    }

    public string DecryptString(byte[] ciphertext) => Encoding.UTF8.GetString(DecryptBytes(ciphertext));

    public byte[] EncryptBytes(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var output = new byte[CipherFormat.HeaderSize + CipherFormat.TagSize + plaintext.Length];
        CipherFormat.WriteHeader(output, keyId: 0, new byte[CipherFormat.NonceSize]);
        plaintext.CopyTo(output, CipherFormat.HeaderSize + CipherFormat.TagSize);
        return output;
    }

    public byte[] DecryptBytes(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        if (ciphertext.Length < CipherFormat.MinimumCiphertextLength)
        {
            throw new ArgumentException("Ciphertext too short.", nameof(ciphertext));
        }

        return ciphertext[(CipherFormat.HeaderSize + CipherFormat.TagSize)..];
    }
}
