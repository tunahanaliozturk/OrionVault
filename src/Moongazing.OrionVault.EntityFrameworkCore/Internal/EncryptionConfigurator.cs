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

                // Case 1: the property's CLR type is itself a supported provider type. Attach the
                // OrionVault encryption converter directly (model == provider == string / byte[]).
                if (prop.ClrType == typeof(string) || prop.ClrType == typeof(byte[]))
                {
                    prop.SetValueConverter(_factory.For(prop.ClrType));
                    continue;
                }

                // Case 2: the CLR type is unsupported on its own (e.g. a value object such as a
                // `Tckn` record), BUT the consumer has already mapped it with a value converter
                // whose PROVIDER type is string or byte[] (e.g. `.HasConversion(v => v.Value,
                // s => new Tckn(s))`). Compose OrionVault's encryption on TOP of that converter so
                // the column stores the encrypted form of the converted provider value, and reads
                // run decrypt -> the existing FromProvider. ComposeWith chains the converters such
                // that the result of the first conversion feeds the second: on write,
                // model -> existing.ToProvider (-> string/byte[]) -> encrypt; on read,
                // ciphertext -> decrypt -> existing.FromProvider -> model.
                var existing = prop.GetValueConverter();
                if (existing is not null
                    && (existing.ProviderClrType == typeof(string) || existing.ProviderClrType == typeof(byte[])))
                {
                    var composed = existing.ComposeWith(_factory.For(existing.ProviderClrType));
                    prop.SetValueConverter(composed);
                    continue;
                }

                // Case 3: not a supported CLR type and no value converter to a supported provider
                // type. This is genuinely unsupported - preserve the original diagnostic exactly.
                throw new OrionVaultConfigurationException(
                    $"Property '{entityType.ClrType.Name}.{prop.Name}' has type '{prop.ClrType}' which OrionVault does not support. " +
                    "Supported types: string, byte[].");
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
