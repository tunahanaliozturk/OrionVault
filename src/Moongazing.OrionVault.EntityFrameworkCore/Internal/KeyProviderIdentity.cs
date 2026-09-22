namespace Moongazing.OrionVault.EntityFrameworkCore.Internal;

using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.CompilerServices;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;

/// <summary>
/// A collision-free identity for the key provider a DbContext's encrypted columns are bound to.
/// Feeds <see cref="OrionVaultModelCacheKeyFactory"/> so EF Core's process-wide compiled-model cache
/// cannot hand one host's captured encryptor to another host of the same DbContext CLR type.
/// </summary>
/// <remarks>
/// <para>
/// The identity is an opaque number minted on first use and held against the provider in a
/// <see cref="ConditionalWeakTable{TKey, TValue}"/>. Two distinct provider instances can never
/// collide, whatever their configuration; the same instance always answers the same id.
/// </para>
/// <para>
/// This deliberately does NOT fingerprint the key material. An earlier revision hashed the provider
/// type, active key id, key count and the active key's bytes, which let two containers built from
/// one configuration share a compiled model - but it also meant two providers agreeing on all of
/// those while differing in a LEGACY key shared one. That is not an exotic corner: it is the
/// rotation / cutover shape, where tenants most plausibly agree on the active key and differ below
/// it, so the cross-tenant leak stayed open on exactly the path this factory exists to close.
/// Fingerprinting the whole key set is not available either - <see cref="IKeyProvider.TryGetKey"/>
/// is a lookup with no enumeration, and probing the 16-bit id space would be a network call per id
/// against a KMS-backed provider. Discriminating per instance sidesteps both.
/// </para>
/// <para>
/// The cost is one compiled model per provider instance rather than per distinct key set. Every
/// <see cref="IKeyProvider"/> OrionVault registers is a container singleton (the static, KMS and
/// testing registrations all use <c>AddSingleton</c>, and
/// <see cref="IKeyedKeyProviderRegistry"/> hands back a stored instance), so that is one model per
/// container - the number a correct cache would build anyway.
/// </para>
/// <para>
/// A minted id rather than the provider object itself: a provider that overrides
/// <see cref="object.Equals(object)"/> - a record-shaped one, say - would make two distinct
/// instances compare equal and share a model again, which is the bug this closes.
/// </para>
/// </remarks>
internal static class KeyProviderIdentity
{
    /// <summary>Stands in for "no OrionVault key provider is reachable from this context".</summary>
    public static readonly object None = "OrionVault:no-key-provider";

    private static long nextId;

    private static readonly ConditionalWeakTable<IKeyProvider, object> Ids = [];

    private static readonly ConcurrentDictionary<Type, (Type BindingType, PropertyInfo ProviderName)> Bindings = new();

    /// <summary>
    /// The identity of the key provider bound to <paramref name="context"/>, or <see cref="None"/>
    /// when nothing OrionVault registered is reachable from it.
    /// </summary>
    public static object ForContext(DbContext context)
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
            return None;
        }

        var keys = ResolveKeyProvider(applicationSp, context.GetType());
        return keys is null ? None : For(keys);
    }

    /// <summary>The identity of <paramref name="keys"/>; minted once per instance.</summary>
    public static object For(IKeyProvider keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        return Ids.GetValue(keys, static _ => Interlocked.Increment(ref nextId));
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
}
