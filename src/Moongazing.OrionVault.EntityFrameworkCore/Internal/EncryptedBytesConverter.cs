namespace Moongazing.OrionVault.EntityFrameworkCore.Internal;

using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Moongazing.OrionVault.Abstractions;

internal sealed class EncryptedBytesConverter : ValueConverter<byte[], byte[]>
{
    public EncryptedBytesConverter(IEncryptor encryptor)
        : base(
            v => encryptor.EncryptBytes(v),
            v => encryptor.DecryptBytes(v))
    { }
}
