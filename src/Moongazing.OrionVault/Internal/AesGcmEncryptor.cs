namespace Moongazing.OrionVault.Internal;

using System.Security.Cryptography;
using System.Text;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Exceptions;

internal sealed class AesGcmEncryptor : IEncryptor
{
    private const int KeyLengthBytes = 32;
    private readonly IKeyProvider _keys;

    public AesGcmEncryptor(IKeyProvider keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        _keys = keys;
    }

    public byte[] EncryptString(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        return EncryptInternal(bytes);
    }

    public string DecryptString(byte[] ciphertext)
    {
        var plain = DecryptInternal(ciphertext);
        return Encoding.UTF8.GetString(plain);
    }

    public byte[] EncryptBytes(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return EncryptInternal(plaintext);
    }

    public byte[] DecryptBytes(byte[] ciphertext) => DecryptInternal(ciphertext);

    private byte[] EncryptInternal(ReadOnlySpan<byte> plaintext)
    {
        var keyId = _keys.ActiveKeyId;
        var key = _keys.TryGetKey(keyId)
            ?? throw new OrionVaultConfigurationException(
                $"Active key id {keyId} is not registered in the IKeyProvider.");
        if (key.Length != KeyLengthBytes)
            throw new OrionVaultConfigurationException(
                $"Key {keyId} is {key.Length} bytes; expected {KeyLengthBytes}.");

        var output = new byte[CipherFormat.HeaderSize + CipherFormat.TagSize + plaintext.Length];
        var nonce = output.AsSpan(CipherFormat.KeyIdSize, CipherFormat.NonceSize);
        RandomNumberGenerator.Fill(nonce);

        CipherFormat.WriteHeader(output, keyId, nonce);
        var tag = output.AsSpan(CipherFormat.HeaderSize, CipherFormat.TagSize);
        var body = output.AsSpan(CipherFormat.HeaderSize + CipherFormat.TagSize);

        using var aes = new AesGcm(key.Span, CipherFormat.TagSize);
        aes.Encrypt(nonce, plaintext, body, tag);
        return output;
    }

    private byte[] DecryptInternal(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        if (ciphertext.Length < CipherFormat.MinimumCiphertextLength)
            throw new OrionVaultDecryptionException(
                $"Ciphertext length {ciphertext.Length} is below the minimum {CipherFormat.MinimumCiphertextLength}.");

        var keyId = CipherFormat.ReadKeyId(ciphertext);
        var keyLookup = _keys.TryGetKey(keyId);
        if (!keyLookup.HasValue || keyLookup.Value.IsEmpty)
            throw new OrionVaultKeyNotFoundException(keyId);
        var key = keyLookup.Value;

        var nonce = CipherFormat.ReadNonce(ciphertext);
        var tag = CipherFormat.ReadTag(ciphertext);
        var body = CipherFormat.ReadBody(ciphertext);
        var plaintext = new byte[body.Length];

        try
        {
            using var aes = new AesGcm(key.Span, CipherFormat.TagSize);
            aes.Decrypt(nonce, body, tag, plaintext);
            return plaintext;
        }
        catch (CryptographicException ex)
        {
            throw new OrionVaultDecryptionException(
                "Ciphertext failed authentication (tampered, wrong key, or corrupted).", ex);
        }
    }
}
