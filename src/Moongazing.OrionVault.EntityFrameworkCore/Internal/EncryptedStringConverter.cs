namespace Moongazing.OrionVault.EntityFrameworkCore.Internal;

using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Moongazing.OrionVault.Abstractions;

internal sealed class EncryptedStringConverter : ValueConverter<string, byte[]>
{
    public EncryptedStringConverter(IEncryptor encryptor)
        : base(
            v => encryptor.EncryptString(v),
            v => encryptor.DecryptString(v))
    { }
}
