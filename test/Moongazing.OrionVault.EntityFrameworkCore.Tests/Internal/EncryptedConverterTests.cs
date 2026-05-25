namespace Moongazing.OrionVault.EntityFrameworkCore.Tests.Internal;

using FluentAssertions;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.EntityFrameworkCore.Internal;
using Moongazing.OrionVault.Internal;
using Xunit;

public class EncryptedConverterTests
{
    private static readonly byte[] Key = new byte[32];
    private static readonly OrionVaultDiagnostics Diag = new();

    private sealed class OneKey : IKeyProvider
    {
        public short ActiveKeyId => 1;
        public ReadOnlyMemory<byte>? TryGetKey(short keyId) => keyId == 1 ? Key : null;
    }

    [Fact]
    public void EncryptedStringConverter_round_trips_via_EF_value_converter_API()
    {
        var encryptor = new AesGcmEncryptor(new OneKey(), Diag);
        var sut = new EncryptedStringConverter(encryptor);

        var modelValue = "hello";
        var providerValue = (byte[])sut.ConvertToProvider(modelValue)!;
        var back = (string)sut.ConvertFromProvider(providerValue)!;

        back.Should().Be("hello");
    }

    [Fact]
    public void EncryptedBytesConverter_round_trips_via_EF_value_converter_API()
    {
        var encryptor = new AesGcmEncryptor(new OneKey(), Diag);
        var sut = new EncryptedBytesConverter(encryptor);

        var modelValue = new byte[] { 1, 2, 3 };
        var providerValue = (byte[])sut.ConvertToProvider(modelValue)!;
        var back = (byte[])sut.ConvertFromProvider(providerValue)!;

        back.Should().Equal(modelValue);
    }

    [Fact]
    public void Factory_returns_string_converter_for_string_clr_type()
    {
        var encryptor = new AesGcmEncryptor(new OneKey(), Diag);
        var factory = new EncryptedValueConverterFactory(encryptor);

        var converter = factory.For(typeof(string));
        converter.Should().BeOfType<EncryptedStringConverter>();
    }

    [Fact]
    public void Factory_returns_bytes_converter_for_byte_array_clr_type()
    {
        var encryptor = new AesGcmEncryptor(new OneKey(), Diag);
        var factory = new EncryptedValueConverterFactory(encryptor);

        var converter = factory.For(typeof(byte[]));
        converter.Should().BeOfType<EncryptedBytesConverter>();
    }

    [Fact]
    public void Factory_throws_for_unsupported_type()
    {
        var encryptor = new AesGcmEncryptor(new OneKey(), Diag);
        var factory = new EncryptedValueConverterFactory(encryptor);

        var act = () => factory.For(typeof(int));
        act.Should().Throw<Moongazing.OrionVault.Exceptions.OrionVaultConfigurationException>()
            .WithMessage("*int*");
    }
}
