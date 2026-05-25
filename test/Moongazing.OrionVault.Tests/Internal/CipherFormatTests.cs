namespace Moongazing.OrionVault.Tests.Internal;

using FluentAssertions;
using Moongazing.OrionVault.Internal;
using Xunit;

public class CipherFormatTests
{
    [Fact]
    public void WriteHeader_writes_keyId_big_endian()
    {
        Span<byte> buffer = stackalloc byte[CipherFormat.HeaderSize];
        Span<byte> nonce = stackalloc byte[12];
        nonce.Fill(0xAA);

        CipherFormat.WriteHeader(buffer, keyId: 0x0102, nonce);

        buffer[0].Should().Be(0x01);
        buffer[1].Should().Be(0x02);
        for (int i = 0; i < 12; i++) buffer[2 + i].Should().Be(0xAA);
    }

    [Fact]
    public void ReadKeyId_round_trips_with_WriteHeader()
    {
        Span<byte> buffer = stackalloc byte[CipherFormat.HeaderSize];
        Span<byte> nonce = stackalloc byte[12];
        CipherFormat.WriteHeader(buffer, keyId: 7, nonce);

        CipherFormat.ReadKeyId(buffer).Should().Be(7);
    }

    [Fact]
    public void Constants_match_spec()
    {
        CipherFormat.KeyIdSize.Should().Be(2);
        CipherFormat.NonceSize.Should().Be(12);
        CipherFormat.TagSize.Should().Be(16);
        CipherFormat.HeaderSize.Should().Be(14);
        CipherFormat.MinimumCiphertextLength.Should().Be(30);
    }
}
