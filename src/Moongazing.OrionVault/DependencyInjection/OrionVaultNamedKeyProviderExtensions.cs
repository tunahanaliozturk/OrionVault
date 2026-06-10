namespace Moongazing.OrionVault.DependencyInjection;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Internal;

/// <summary>
/// Named-provider registration helpers. Foundation for v0.3.0's per-DbContext provider
/// binding; v0.2.7 ships the DI plumbing so consumers can populate the registry today and
/// the v0.3 EF Core overload can resolve named providers without breaking changes.
/// </summary>
public static class OrionVaultNamedKeyProviderExtensions
{
    /// <summary>
    /// Register <paramref name="provider"/> in the named-provider registry under
    /// <paramref name="name"/>. The registry is registered as a singleton on first call;
    /// subsequent calls share the same instance. Idempotent on (name, provider) - the
    /// first registration for a given name wins.
    /// </summary>
    /// <param name="builder">The OrionVault builder.</param>
    /// <param name="name">Logical name (e.g. <c>"primary"</c>, <c>"audit"</c>).</param>
    /// <param name="provider">The key provider instance.</param>
    /// <returns>The same <paramref name="builder"/> for chaining.</returns>
    public static OrionVaultBuilder AddNamedKeyProvider(
        this OrionVaultBuilder builder, string name, IKeyProvider provider)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(provider);

        EnsureRegistryRegistered(builder.Services);
        // Resolve a singleton snapshot to populate the registry at startup. AddSingleton
        // (NOT TryAddSingleton) is fine because the registry implementation is internal
        // and we want our singleton to win; the registry inside is reused for all
        // AddNamedKeyProvider calls on the same Services collection.
        builder.Services.AddSingleton<IConfigureNamedKeyProvider>(
            new ConfigureNamedKeyProvider(name, _ => provider));

        return builder;
    }

    /// <summary>
    /// Register a named provider whose construction depends on the service provider
    /// (e.g. reading an AwsKms client out of DI). The factory runs once during registry
    /// initialisation.
    /// </summary>
    public static OrionVaultBuilder AddNamedKeyProvider(
        this OrionVaultBuilder builder, string name, Func<IServiceProvider, IKeyProvider> factory)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(factory);

        EnsureRegistryRegistered(builder.Services);
        builder.Services.AddSingleton<IConfigureNamedKeyProvider>(
            new ConfigureNamedKeyProvider(name, factory));

        return builder;
    }

    private static void EnsureRegistryRegistered(IServiceCollection services)
    {
        services.TryAddSingleton<KeyedKeyProviderRegistry>();
        services.TryAddSingleton<IKeyedKeyProviderRegistry>(sp =>
        {
            var registry = sp.GetRequiredService<KeyedKeyProviderRegistry>();
            // Drain all IConfigureNamedKeyProvider registrations into the registry. The
            // DI container resolves these in registration order so the same order is
            // preserved in IKeyedKeyProviderRegistry.RegisteredNames().
            foreach (var configurator in sp.GetServices<IConfigureNamedKeyProvider>())
            {
                registry.Register(configurator.Name, configurator.Factory(sp));
            }
            return registry;
        });
    }

    /// <summary>
    /// DI-friendly carrier for a named-provider registration. The DI container collects
    /// every <see cref="IConfigureNamedKeyProvider"/> registered on the collection and the
    /// registry initialiser drains them into the registry on first resolve.
    /// </summary>
    internal interface IConfigureNamedKeyProvider
    {
        string Name { get; }
        Func<IServiceProvider, IKeyProvider> Factory { get; }
    }

    private sealed class ConfigureNamedKeyProvider : IConfigureNamedKeyProvider
    {
        public ConfigureNamedKeyProvider(string name, Func<IServiceProvider, IKeyProvider> factory)
        {
            Name = name;
            Factory = factory;
        }
        public string Name { get; }
        public Func<IServiceProvider, IKeyProvider> Factory { get; }
    }
}
