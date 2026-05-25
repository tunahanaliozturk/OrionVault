namespace Moongazing.OrionVault.EntityFrameworkCore.Internal;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Exceptions;

internal sealed class EncryptionConfigurator : IEncryptionConfigurator
{
    private readonly EncryptedValueConverterFactory _factory;

    public EncryptionConfigurator(EncryptedValueConverterFactory factory)
    {
        ArgumentNullException.ThrowIfNull(factory);
        _factory = factory;
    }

    public void Configure(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            foreach (var prop in entityType.GetProperties())
            {
                if (!ShouldEncrypt(prop))
                {
                    continue;
                }

                if (prop.ClrType != typeof(string) && prop.ClrType != typeof(byte[]))
                {
                    throw new OrionVaultConfigurationException(
                        $"Property '{entityType.ClrType.Name}.{prop.Name}' has type '{prop.ClrType}' which OrionVault does not support. " +
                        "Supported types: string, byte[].");
                }

                prop.SetValueConverter(_factory.For(prop.ClrType));
            }
        }
    }

    private static bool ShouldEncrypt(IMutableProperty prop)
    {
        if (prop.FindAnnotation(PropertyBuilderExtensions.EncryptedAnnotation)?.Value is true)
        {
            return true;
        }

        var clrProp = prop.PropertyInfo;
        if (clrProp is not null && clrProp.GetCustomAttributes(typeof(EncryptedAttribute), inherit: true).Length > 0)
        {
            return true;
        }

        return false;
    }
}
