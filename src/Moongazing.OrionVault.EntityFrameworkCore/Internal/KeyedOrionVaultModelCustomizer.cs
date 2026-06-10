namespace Moongazing.OrionVault.EntityFrameworkCore;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;

/// <summary>
/// v0.2.9 model customizer that applies a <typeparamref name="TDbContext"/>-bound keyed
/// <see cref="IEncryptionConfigurator"/> on the model. Pairs with the v0.2.8
/// <c>UseEntityFrameworkCore&lt;TDbContext&gt;(providerName)</c> registration and the
/// v0.2.9 <see cref="KeyedOrionVaultBinding{TDbContext}"/> registration:
/// </summary>
/// <typeparam name="TDbContext">The DbContext this customizer scopes.</typeparam>
/// <remarks>
/// <para>
/// Wire via:
/// </para>
/// <code>
/// services.AddOrionVault(...)
///     .AddNamedKeyProvider("primary", primaryKeyProvider)
///     .UseEntityFrameworkCore&lt;PrimaryDb&gt;("primary");
/// services.AddSingleton(new KeyedOrionVaultBinding&lt;PrimaryDb&gt;("primary"));
/// services.AddDbContext&lt;PrimaryDb&gt;((sp, opt) =&gt;
/// {
///     opt.UseSqlServer(connectionString);
///     opt.UseApplicationServiceProvider(sp);
///     opt.ReplaceService&lt;IModelCustomizer, KeyedOrionVaultModelCustomizer&lt;PrimaryDb&gt;&gt;();
/// });
/// </code>
/// <para>
/// The customizer has a parameterless ctor (so EF Core's internal SP can construct it via
/// <see cref="DbContextOptionsBuilder.ReplaceService{TService,TImplementation}"/>); its
/// <see cref="Customize"/> reads from the application SP attached via
/// <see cref="DbContextOptionsBuilder.UseApplicationServiceProvider"/>. Without
/// UseApplicationServiceProvider the application SP is not visible to EF Core and the
/// resolve will throw at first model build.
/// </para>
/// </remarks>
public sealed class KeyedOrionVaultModelCustomizer<TDbContext> : IModelCustomizer
    where TDbContext : DbContext
{
#pragma warning disable EF1001 // ModelCustomizerDependencies is an internal EF Core API but the parameterless ctor is the documented pattern
    private readonly ModelCustomizerDependencies dependencies;

    /// <summary>Parameterless ctor required for EF Core's ReplaceService construction.</summary>
    public KeyedOrionVaultModelCustomizer()
    {
        dependencies = new ModelCustomizerDependencies();
    }
#pragma warning restore EF1001

    /// <inheritdoc />
    public void Customize(ModelBuilder modelBuilder, DbContext context)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        ArgumentNullException.ThrowIfNull(context);

        // Provider-aware default customization: ReplaceService<IModelCustomizer, ...>
        // swaps the provider's own customizer for ours, so a fresh plain ModelCustomizer
        // here would lose provider-specific behaviours (SQL Server temporal tables,
        // Cosmos document hints, etc.). Discover the original customizer registered on
        // the internal SP via the dependencies' service provider snapshot and delegate
        // to it - that preserves the provider chain.
#pragma warning disable EF1001
        var inner = context.GetInfrastructure()
            .GetServices<IModelCustomizer>()
            .FirstOrDefault(c => c is not KeyedOrionVaultModelCustomizer<TDbContext>)
            ?? new ModelCustomizer(dependencies);
#pragma warning restore EF1001
        inner.Customize(modelBuilder, context);

        // The application SP attached via UseApplicationServiceProvider lives on
        // CoreOptionsExtension.ApplicationServiceProvider. EF Core's own internal SP does
        // NOT expose keyed-service support, so we MUST resolve the binding + keyed
        // configurator through the application SP rather than via context.GetService<>.
        var applicationSp = context.GetService<IDbContextOptions>()
            .FindExtension<Microsoft.EntityFrameworkCore.Infrastructure.CoreOptionsExtension>()
            ?.ApplicationServiceProvider
            ?? throw new InvalidOperationException(
                "KeyedOrionVaultModelCustomizer requires UseApplicationServiceProvider on the " +
                "DbContextOptionsBuilder so the application's keyed services are visible.");

        var binding = applicationSp.GetRequiredService<KeyedOrionVaultBinding<TDbContext>>();
        var configurator = applicationSp.GetRequiredKeyedService<IEncryptionConfigurator>(binding.ProviderName);
        configurator.Configure(modelBuilder);
    }
}
