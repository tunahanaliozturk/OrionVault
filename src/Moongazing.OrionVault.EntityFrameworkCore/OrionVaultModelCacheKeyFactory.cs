namespace Moongazing.OrionVault.EntityFrameworkCore;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore.Internal;
using Moongazing.OrionVault.Exceptions;

/// <summary>
/// Adds the bound key provider to EF Core's compiled-model cache key, so two hosts of the SAME
/// DbContext CLR type wired to DIFFERENT keys get different compiled models. Composes with whatever
/// <see cref="IModelCacheKeyFactory"/> the application had already replaced, rather than displacing it.
/// </summary>
/// <remarks>
/// <para>
/// OrionVault's value converters capture one <see cref="Abstractions.IEncryptor"/> by closure, and
/// the converters live on the compiled model. EF Core's default <c>IModelCacheKeyFactory</c> keys
/// that model on the DbContext type (and the design-time flag) alone, and the model cache is
/// process-wide - so without this replacement whichever host built the model first lends its
/// encryptor to every later host of the same type, and one tenant reads another's plaintext.
/// </para>
/// <para>
/// The key is a pair: whatever the INNER factory produced, plus OrionVault's key-provider identity.
/// An application that discriminates its model on something OrionVault knows nothing about -
/// schema-per-tenant is the usual reason, and it is the same audience as this library - keeps its
/// dimension, and gains OrionVault's. The inner factory is EF Core's default when the application
/// replaced nothing.
/// </para>
/// <para>
/// Wired automatically by <c>UseOrionVault(sp)</c>, <c>AddOrionVaultDbContext&lt;T&gt;</c> and
/// <c>AddOrionVaultBoundDbContext&lt;T&gt;</c>, each of which captures the application's own
/// replacement first. Call <c>UseOrionVault</c> AFTER your own <c>ReplaceService</c> calls: a
/// <c>ReplaceService&lt;IModelCacheKeyFactory, …&gt;</c> made afterwards overwrites this one, and
/// OrionVault then refuses to build the model rather than let the discrimination go missing.
/// </para>
/// </remarks>
public sealed class OrionVaultModelCacheKeyFactory : IModelCacheKeyFactory
{
    /// <inheritdoc />
    public object Create(DbContext context, bool designTime)
    {
        ArgumentNullException.ThrowIfNull(context);

        return (ResolveInner(context).Create(context, designTime), KeyProviderIdentity.ForContext(context));
    }

    /// <summary>
    /// Throws unless this factory is the one EF Core will actually use for
    /// <paramref name="context"/>. Called from the model customizers, i.e. on every model build.
    /// </summary>
    /// <remarks>
    /// A <c>ReplaceService&lt;IModelCacheKeyFactory, …&gt;</c> made AFTER <c>UseOrionVault</c>
    /// overwrites OrionVault's replacement, and the options carry no record that it happened. The
    /// consequence would be the silent cross-tenant leak this factory exists to close, so it is
    /// turned into a refusal to build the model instead.
    /// </remarks>
    internal static void EnsureActive(DbContext context)
    {
        var active = context.GetService<IModelCacheKeyFactory>();
        if (active is OrionVaultModelCacheKeyFactory)
        {
            return;
        }

        throw new OrionVaultConfigurationException(
            $"OrionVault is configured on '{context.GetType().Name}' but '{active.GetType().Name}' is the " +
            "active IModelCacheKeyFactory, so the compiled model is not keyed on the bound key provider. " +
            "EF Core's model cache is process-wide and its default key is the DbContext type alone, so a " +
            "second host of this context type with different keys would reuse this one's model - and its " +
            "encryptor - and read its plaintext. A ReplaceService<IModelCacheKeyFactory, ...> call made " +
            "after UseOrionVault silently overwrites OrionVault's; move that call BEFORE UseOrionVault and " +
            "OrionVault will compose with it, keeping both dimensions of the key.");
    }

    private static IModelCacheKeyFactory ResolveInner(DbContext context)
    {
        var innerType = context.GetService<IDbContextOptions>()
            .FindExtension<OrionVaultOptionsExtension>()
            ?.InnerModelCacheKeyFactory;

        if (innerType is null)
        {
            // Nothing was replaced before us, so the inner key is the one EF Core would have built.
            return DefaultModelCacheKeyFactory.Instance;
        }

        // OrionVaultOptionsExtension.ApplyServices re-registered the captured type into EF Core's
        // internal container, so EF constructs it with its own dependencies.
        return (IModelCacheKeyFactory)context.GetInfrastructure().GetRequiredService(innerType);
    }

    private static class DefaultModelCacheKeyFactory
    {
#pragma warning disable EF1001 // ModelCacheKeyFactoryDependencies is an internal EF Core API; the
        // parameterless dependency-bag construction is the same pattern OrionVaultModelCustomizer
        // uses to stand up EF Core's own default implementation.
        public static readonly IModelCacheKeyFactory Instance =
            new ModelCacheKeyFactory(new ModelCacheKeyFactoryDependencies());
#pragma warning restore EF1001
    }
}
