namespace Moongazing.OrionVault.EntityFrameworkCore.Internal;

using System.Collections.Concurrent;
using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;

/// <summary>
/// A stable, non-secret identity for the key material a DbContext's encrypted columns are bound to.
/// Feeds <see cref="OrionVaultModelCacheKeyFactory"/> so EF Core's process-wide compiled-model cache
/// cannot hand one host's captured encryptor to another host of the same DbContext CLR type.
/// </summary>
/// <remarks>
/// <para>
/// The identity is a truncated SHA-256 digest over the key provider's type, its active key id, its
/// reported key count and the ACTIVE key's bytes. That is deliberately neither of the two obvious
/// choices: a provider TYPE NAME is the same for two <c>StaticKeyProvider</c>s holding different
/// keys, and an object REFERENCE changes every time the container is rebuilt, which would compile
/// and cache a fresh model per container for the life of the process.
/// </para>
/// <para>
/// The digest is one-way and truncated, so it discloses nothing about the key; it is only ever used
/// as a dictionary discriminator.
/// </para>
/// <para>
/// Residual: two providers of the same type that agree on active key, key count and active key bytes
/// but differ in a LEGACY (non-active) key produce the same fingerprint and would share a model.
/// Closing that would mean enumerating every key, which <see cref="IKeyProvider"/> cannot do
/// (<see cref="IKeyProvider.TryGetKey"/> is a lookup, and probing the whole 16-bit id space would be
/// a network call per id for a KMS-backed provider).
/// </para>
/// </remarks>
internal static class KeySetFingerprint
{
    private const string Domain = "OrionVault/model-cache/v1";

    // Keyed on the provider INSTANCE: the fingerprint is asked for once per DbContext construction,
    // and this keeps that to a dictionary probe instead of a hash. The table holds no strong
    // reference, so a discarded container's provider is still collectable.
    private static readonly ConditionalWeakTable<IKeyProvider, string> Cache = [];

    private static readonly ConcurrentDictionary<Type, (Type BindingType, PropertyInfo ProviderName)> Bindings = new();

    /// <summary>
    /// The fingerprint of the key material bound to <paramref name="context"/>, or an empty string
    /// when no OrionVault key provider is reachable from it (nothing was bound, so there is nothing
    /// to discriminate).
    /// </summary>
    public static string ForContext(DbContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Same lookup the model customizers use: the application container is attached to the
        // options by UseApplicationServiceProvider, and EF Core's own internal provider cannot see
        // application registrations.
        var applicationSp = context.GetService<IDbContextOptions>()
            .FindExtension<CoreOptionsExtension>()
            ?.ApplicationServiceProvider;

        if (applicationSp is null)
        {
            return string.Empty;
        }

        var keys = ResolveKeyProvider(applicationSp, context.GetType());
        return keys is null ? string.Empty : For(keys);
    }

    /// <summary>The fingerprint of <paramref name="keys"/>; computed once per provider instance.</summary>
    public static string For(IKeyProvider keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        return Cache.GetValue(keys, Compute);
    }

    // Two wirings reach a key provider, and which one is in play is decided by whether the
    // per-DbContext keyed binding is registered:
    //   AddOrionVaultBoundDbContext<T>(name) / KeyedOrionVaultModelCustomizer<T> -> named provider,
    //   UseOrionVault(sp) / AddOrionVaultDbContext<T>                            -> the global one.
    // The binding type is generic in the DbContext, which this non-generic factory does not know at
    // compile time, so the closed type and its accessor are reflected once per context type.
    private static IKeyProvider? ResolveKeyProvider(IServiceProvider applicationSp, Type contextType)
    {
        var (bindingType, providerNameProperty) = Bindings.GetOrAdd(contextType, static type =>
        {
            var closed = typeof(KeyedOrionVaultBinding<>).MakeGenericType(type);
            return (closed, closed.GetProperty(nameof(KeyedOrionVaultBinding<DbContext>.ProviderName))!);
        });

        if (applicationSp.GetService(bindingType) is { } binding
            && providerNameProperty.GetValue(binding) is string providerName)
        {
            return applicationSp.GetRequiredService<IKeyedKeyProviderRegistry>().GetProvider(providerName);
        }

        return applicationSp.GetService<IKeyProvider>();
    }

    private static string Compute(IKeyProvider keys)
    {
        var activeKeyId = keys.ActiveKeyId;
        var material = keys.TryGetKey(activeKeyId) ?? ReadOnlyMemory<byte>.Empty;

        var header = Encoding.UTF8.GetBytes(string.Create(
            CultureInfo.InvariantCulture,
            $"{Domain}|{keys.GetType().AssemblyQualifiedName}|{activeKeyId}|{keys.KeyCount}|"));

        var input = new byte[header.Length + material.Length];
        try
        {
            header.CopyTo(input, 0);
            material.Span.CopyTo(input.AsSpan(header.Length));

            // 128 bits of a SHA-256 digest: far past any chance of an accidental collision between
            // two key sets, and short enough to keep the cache key cheap to compare.
            return Convert.ToHexString(SHA256.HashData(input).AsSpan(0, 16));
        }
        finally
        {
            // The buffer held the active key; do not leave a second copy of it on the heap.
            CryptographicOperations.ZeroMemory(input);
        }
    }
}
