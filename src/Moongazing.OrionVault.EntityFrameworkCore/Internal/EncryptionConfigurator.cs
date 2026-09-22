namespace Moongazing.OrionVault.EntityFrameworkCore.Internal;

using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Exceptions;
using Moongazing.OrionVault.Internal;

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

                // Refuse the roles the ciphertext cannot fill BEFORE attaching anything: a model that
                // would silently stop matching is worse than one that will not build.
                RejectIdentityRoles(entityType, prop);

                // Case 1: the property's CLR type is itself a supported provider type. Attach the
                // OrionVault encryption converter directly (model == provider == string / byte[]).
                if (prop.ClrType == typeof(string) || prop.ClrType == typeof(byte[]))
                {
                    prop.SetValueConverter(_factory.For(prop.ClrType));
                    WidenMaxLengthForEnvelope(prop, prop.ClrType);
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
                    // The declared length was sized for what the EXISTING converter produced, so that
                    // is the plaintext the envelope now wraps - not the CLR type of the property.
                    WidenMaxLengthForEnvelope(prop, existing.ProviderClrType);
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

    /// <summary>
    /// The column now stores ciphertext, so a <c>MaxLength</c> the consumer sized for plaintext no
    /// longer describes what has to fit. Widen it to cover the AES-GCM envelope of a maximum-length
    /// plaintext; a store that enforces length would otherwise reject the write, or - far worse -
    /// truncate it, cutting the GCM tag and leaving a row no key can ever decrypt.
    /// </summary>
    /// <remarks>
    /// The facet is widened rather than cleared. Clearing it (unbounded binary) would silently turn
    /// every encrypted column into <c>varbinary(max)</c> / <c>BLOB</c>, throwing away the consumer's
    /// stated size budget, the index-width limits it keeps them inside, and any row-size planning
    /// built on it. Widening keeps the column bounded and keeps the consumer's intent legible.
    /// </remarks>
    private static void WidenMaxLengthForEnvelope(IMutableProperty prop, Type plaintextProviderType)
    {
        if (prop.GetMaxLength() is not int declared || declared < 0)
        {
            // Unbounded already: nothing to widen, and nothing to overflow.
            return;
        }

        // A string's MaxLength counts CHARACTERS (UTF-16 code units) but the encryptor consumes UTF-8
        // BYTES, and outside the ASCII range that is more than one byte per character. GetMaxByteCount
        // is the framework's own worst case (3n + 3: three bytes per BMP code unit, plus room for a
        // dangling surrogate), so the widened column fits any string the consumer's own facet admits.
        var plaintextBytes = plaintextProviderType == typeof(string)
            ? Encoding.UTF8.GetMaxByteCount(declared)
            : declared;

        prop.SetMaxLength(CipherFormat.MinimumCiphertextLength + plaintextBytes);
    }

    /// <summary>
    /// Refuses the model roles that a randomised ciphertext cannot fill. AES-GCM draws a fresh nonce
    /// on every write, so the stored bytes differ each time the same plaintext is saved: a unique
    /// index never fires, a key or foreign key never joins, and a concurrency token never matches.
    /// All three fail silently today, which is why this is a build-time refusal rather than a warning.
    /// </summary>
    private static void RejectIdentityRoles(IMutableEntityType entityType, IMutableProperty prop)
    {
        var (role, remedy) = Diagnose(entityType, prop);
        if (role is null)
        {
            return;
        }

        throw new OrionVaultConfigurationException(
            $"Property '{entityType.ClrType.Name}.{prop.Name}' is encrypted and is {role}. " +
            "OrionVault encrypts with AES-GCM under a fresh nonce per write, so the stored value is " +
            "different every time the same plaintext is saved - the comparison this role depends on " +
            $"can never match. {remedy} " +
            "For an equality lookup or a uniqueness constraint over the plaintext, add a deterministic " +
            "blind-index column (options.UseBlindIndex(...) / IBlindIndexProvider) and put the unique " +
            "index on that, keeping the encrypted column for the value itself.");
    }

    private static (string? Role, string? Remedy) Diagnose(IMutableEntityType entityType, IMutableProperty prop)
    {
        if (prop.IsKey())
        {
            return ("part of a primary or alternate key",
                $"Stop encrypting '{prop.Name}', or key the entity on an unencrypted surrogate.");
        }

        if (prop.IsForeignKey())
        {
            return ("part of a foreign key",
                $"Take the encryption off '{prop.Name}' so the relationship still resolves.");
        }

        if (prop.IsConcurrencyToken)
        {
            return ("a concurrency token",
                $"Use an unencrypted rowversion / token column instead of '{prop.Name}'.");
        }

        if (entityType.GetIndexes().Any(i => i.IsUnique && i.Properties.Contains(prop)))
        {
            return ("covered by a unique index",
                $"Drop the unique index over '{prop.Name}', or stop encrypting the property.");
        }

        return (null, null);
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
