namespace Moongazing.OrionVault.Internal;

using System.Buffers.Binary;

/// <summary>
/// On-disk layout: <c>[keyId:2 BE | nonce:12 | tag:16 | ciphertext:N]</c>.
/// Total fixed overhead is 30 bytes; minimum legal ciphertext length is 30.
/// </summary>
internal static class CipherFormat
{
    public const int KeyIdSize = 2;
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int HeaderSize = KeyIdSize + NonceSize;
    public const int MinimumCiphertextLength = HeaderSize + TagSize;

    public static void WriteHeader(Span<byte> destination, short keyId, ReadOnlySpan<byte> nonce)
    {
        if (destination.Length < HeaderSize)
            throw new ArgumentException($"Destination must be at least {HeaderSize} bytes.", nameof(destination));
        if (nonce.Length != NonceSize)
            throw new ArgumentException($"Nonce must be exactly {NonceSize} bytes.", nameof(nonce));

        BinaryPrimitives.WriteInt16BigEndian(destination[..KeyIdSize], keyId);
        nonce.CopyTo(destination[KeyIdSize..HeaderSize]);
    }

    public static short ReadKeyId(ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length < KeyIdSize)
            throw new ArgumentException($"Ciphertext must be at least {KeyIdSize} bytes to read key id.", nameof(ciphertext));

        return BinaryPrimitives.ReadInt16BigEndian(ciphertext[..KeyIdSize]);
    }

    public static ReadOnlySpan<byte> ReadNonce(ReadOnlySpan<byte> ciphertext)
        => ciphertext.Slice(KeyIdSize, NonceSize);

    public static ReadOnlySpan<byte> ReadTag(ReadOnlySpan<byte> ciphertext)
        => ciphertext.Slice(HeaderSize, TagSize);

    public static ReadOnlySpan<byte> ReadBody(ReadOnlySpan<byte> ciphertext)
        => ciphertext[(HeaderSize + TagSize)..];
}
