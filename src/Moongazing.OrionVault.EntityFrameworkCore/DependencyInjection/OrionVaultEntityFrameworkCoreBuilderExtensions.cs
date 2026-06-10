namespace Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore.Internal;

public static class OrionVaultEntityFrameworkCoreBuilderExtensions
{
    /// <summary>
    /// Register OrionVault's EF Core integration. From v0.2.6 onward this call is
    /// idempotent across multiple <typeparamref name="TDbContext"/> types: the registered
    /// services use <see cref="ServiceCollectionDescriptorExtensions.TryAddSingleton{TService, TImplementation}(IServiceCollection)"/>
    /// shapes so additional <c>UseEntityFrameworkCore&lt;OtherDbContext&gt;()</c> calls
    /// share the same <see cref="IEncryptor"/> + <see cref="IEncryptionConfigurator"/>
    /// singletons without overwriting them.
    /// </summary>
    /// <remarks>
    /// All registered DbContexts share ONE <see cref="IEncryptor"/> and therefore ONE
    /// key-set. This is the common case (primary write DB + audit DB encrypted with the
    /// same KMS-wrapped data keys). Tenants requiring distinct key providers per DbContext
    /// must register OrionVault as a separate keyed service - that contract is targeted
    /// for the v0.3 milestone.
    /// </remarks>
    public static OrionVaultBuilder UseEntityFrameworkCore<TDbContext>(this OrionVaultBuilder builder)
        where TDbContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.TryAddSingleton<EncryptedValueConverterFactory>(sp =>
            new EncryptedValueConverterFactory(sp.GetRequiredService<IEncryptor>()));
        builder.Services.TryAddSingleton<IEncryptionConfigurator>(sp =>
            new EncryptionConfigurator(sp.GetRequiredService<EncryptedValueConverterFactory>()));

        return builder;
    }

    /// <summary>
    /// v0.2.8 per-DbContext binding overload. Registers SEPARATE
    /// <see cref="EncryptedValueConverterFactory"/> and <see cref="IEncryptionConfigurator"/>
    /// keyed under <paramref name="providerName"/>, bound to the named
    /// <see cref="IKeyProvider"/> in <see cref="Abstractions.IKeyedKeyProviderRegistry"/>.
    /// The drop-in EF Core wiring (a <c>UseOrionVault(builder, sp, providerName)</c>
    /// overload that auto-attaches the keyed configurator to a DbContext options pipeline)
    /// is deferred to v0.3.0 - EF Core's <c>ReplaceService</c> does not expose a factory
    /// overload that can capture a keyed dependency at registration time, so v0.3.0 will
    /// use a different mechanism. Until then consumers resolve
    /// <see cref="IEncryptionConfigurator"/> via
    /// <c>sp.GetRequiredKeyedService&lt;IEncryptionConfigurator&gt;(providerName)</c> and
    /// apply it from a custom model customizer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The registry MUST be populated via
    /// <see cref="DependencyInjection.OrionVaultNamedKeyProviderExtensions.AddNamedKeyProvider(OrionVaultBuilder, string, IKeyProvider)"/>
    /// before the DbContext is resolved; the configurator factory walks the registry on
    /// first resolve to build its <see cref="IEncryptor"/>.
    /// </para>
    /// </remarks>
    public static OrionVaultBuilder UseEntityFrameworkCore<TDbContext>(
        this OrionVaultBuilder builder, string providerName)
        where TDbContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(providerName);

        builder.Services.AddKeyedSingleton<IEncryptor>(providerName, (sp, key) =>
        {
            var registry = sp.GetRequiredService<IKeyedKeyProviderRegistry>();
            var provider = registry.GetProvider((string)key!);
            var diag = sp.GetRequiredService<Moongazing.OrionVault.Diagnostics.OrionVaultDiagnostics>();
            return OrionVaultEncryptor.Create(provider, diag);
        });
        builder.Services.AddKeyedSingleton<EncryptedValueConverterFactory>(providerName, (sp, key) =>
            new EncryptedValueConverterFactory(sp.GetRequiredKeyedService<IEncryptor>(key)));
        builder.Services.AddKeyedSingleton<IEncryptionConfigurator>(providerName, (sp, key) =>
            new EncryptionConfigurator(sp.GetRequiredKeyedService<EncryptedValueConverterFactory>(key)));

        return builder;
    }

    /// <summary>
    /// Attach OrionVault's model customizer to a <see cref="DbContextOptionsBuilder"/>.
    /// Call this inside the <c>(sp, opt) =&gt; ...</c> overload of <c>AddDbContext</c>.
    /// Safe to call once per DbContext type; the customizer replacement is per-
    /// <see cref="DbContextOptionsBuilder"/> so two DbContexts wired this way do not
    /// interfere with each other.
    /// </summary>
    public static DbContextOptionsBuilder UseOrionVault(
        this DbContextOptionsBuilder builder,
        IServiceProvider serviceProvider)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(serviceProvider);

        // UseApplicationServiceProvider hands EF Core a handle to the application's container so
        // that replaced services constructed by EF Core's internal SP can pull application-side
        // dependencies (IEncryptionConfigurator here). Without this, ReplaceService below would
        // bind an instance whose ctor cannot satisfy its IEncryptionConfigurator parameter.
        builder.UseApplicationServiceProvider(serviceProvider);
        builder.ReplaceService<IModelCustomizer, OrionVaultModelCustomizer>();
        return builder;
    }

    /// <summary>
    /// Combined registration shortcut: registers OrionVault's EF Core integration for
    /// <typeparamref name="TDbContext"/> AND wires <see cref="UseOrionVault"/> inside an
    /// <see cref="EntityFrameworkServiceCollectionExtensions.AddDbContext{TContext}(IServiceCollection, Action{IServiceProvider, DbContextOptionsBuilder}, ServiceLifetime, ServiceLifetime)"/>
    /// call. Equivalent to writing both halves manually; provided so common single-call
    /// wiring fits in one line. Safe to call once per <typeparamref name="TDbContext"/>
    /// type; calling it for additional DbContext types appends without overwriting.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureContext">
    /// EF Core options callback. The wrapper invokes <see cref="UseOrionVault"/> AFTER the
    /// callback runs so consumer-side provider selection (UseSqlServer / UseNpgsql / etc.)
    /// is applied first and OrionVault attaches on top.
    /// </param>
    /// <param name="contextLifetime">DbContext lifetime; default scoped.</param>
    /// <param name="optionsLifetime">DbContextOptions lifetime; default scoped.</param>
    public static IServiceCollection AddOrionVaultDbContext<TDbContext>(
        this IServiceCollection services,
        Action<IServiceProvider, DbContextOptionsBuilder> configureContext,
        ServiceLifetime contextLifetime = ServiceLifetime.Scoped,
        ServiceLifetime optionsLifetime = ServiceLifetime.Scoped)
        where TDbContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureContext);

        services.TryAddSingleton<EncryptedValueConverterFactory>(sp =>
            new EncryptedValueConverterFactory(sp.GetRequiredService<IEncryptor>()));
        services.TryAddSingleton<IEncryptionConfigurator>(sp =>
            new EncryptionConfigurator(sp.GetRequiredService<EncryptedValueConverterFactory>()));

        services.AddDbContext<TDbContext>(
            (sp, opt) =>
            {
                configureContext(sp, opt);
                opt.UseOrionVault(sp);
            },
            contextLifetime,
            optionsLifetime);
        return services;
    }
}
