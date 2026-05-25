namespace Moongazing.OrionVault.EntityFrameworkCore.Internal;

using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Exceptions;

internal sealed class EncryptedValueConverterFactory
{
    private readonly EncryptedStringConverter _stringConverter;
    private readonly EncryptedBytesConverter _bytesConverter;

    public EncryptedValueConverterFactory(IEncryptor encryptor)
    {
        ArgumentNullException.ThrowIfNull(encryptor);
        _stringConverter = new EncryptedStringConverter(encryptor);
        _bytesConverter = new EncryptedBytesConverter(encryptor);
    }

    public ValueConverter For(Type clrType)
    {
        if (clrType == typeof(string)) return _stringConverter;
        if (clrType == typeof(byte[])) return _bytesConverter;
        throw new OrionVaultConfigurationException(
            $"OrionVault does not support encrypted property type '{clrType}'. " +
            "Supported types are string and byte[].");
    }
}
