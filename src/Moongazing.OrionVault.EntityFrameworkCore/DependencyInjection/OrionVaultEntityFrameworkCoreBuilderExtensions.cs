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
    /// Register OrionVault's EF Core integration bound to <typeparamref name="TDbContext"/>.
    /// </summary>
    /// <remarks>
    /// v0.1.0 supports exactly one OrionVault-bound DbContext per host. Calling
    /// this method twice registers duplicate factories; the second wins and the
    /// first DbContext's encrypted columns become misconfigured. First-class
    /// multi-DbContext support is on the v0.2 roadmap.
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
    /// Attach OrionVault's model customizer to a <see cref="DbContextOptionsBuilder"/>.
    /// Call this inside the <c>(sp, opt) =&gt; ...</c> overload of <c>AddDbContext</c>.
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
}
