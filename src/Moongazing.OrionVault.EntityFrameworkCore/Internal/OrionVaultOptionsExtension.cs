namespace Moongazing.OrionVault.EntityFrameworkCore.Internal;

using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Carries the <c>IModelCacheKeyFactory</c> the application had already replaced, from the point
/// <c>UseOrionVault</c> overwrites that replacement to the point
/// <see cref="OrionVaultModelCacheKeyFactory"/> needs to delegate to it.
/// </summary>
/// <remarks>
/// <para>
/// <c>DbContextOptionsBuilder.ReplaceService&lt;IModelCacheKeyFactory, T&gt;()</c> stores the
/// replacement under the service type alone, so a second call for the same service type silently
/// overwrites the first and the earlier implementation is gone from both
/// <c>CoreOptionsExtension.ReplacedServices</c> and the built provider - enumerating
/// <c>GetServices&lt;IModelCacheKeyFactory&gt;()</c> afterwards returns one entry, ours. The
/// application's type therefore has to be captured BEFORE the overwrite and carried here.
/// </para>
/// <para>
/// <see cref="ApplyServices"/> re-registers the captured type into EF Core's internal container
/// under its own concrete type, so EF constructs it with its normal dependency injection and
/// <see cref="OrionVaultModelCacheKeyFactory"/> only has to resolve it.
/// </para>
/// </remarks>
internal sealed class OrionVaultOptionsExtension : IDbContextOptionsExtension
{
    private DbContextOptionsExtensionInfo? info;

    public OrionVaultOptionsExtension(Type? innerModelCacheKeyFactory)
    {
        InnerModelCacheKeyFactory = innerModelCacheKeyFactory;
    }

    /// <summary>
    /// The factory the application replaced before OrionVault did, or <see langword="null"/> when
    /// OrionVault's replacement was the first and the inner factory is EF Core's default.
    /// </summary>
    public Type? InnerModelCacheKeyFactory { get; }

    public DbContextOptionsExtensionInfo Info => info ??= new ExtensionInfo(this);

    public void ApplyServices(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (InnerModelCacheKeyFactory is not null)
        {
            // Singleton to match the lifetime EF Core gives IModelCacheKeyFactory itself.
            services.AddSingleton(InnerModelCacheKeyFactory);
        }
    }

    public void Validate(IDbContextOptions options)
    {
    }

    private sealed class ExtensionInfo : DbContextOptionsExtensionInfo
    {
        public ExtensionInfo(IDbContextOptionsExtension extension) : base(extension)
        {
        }

        private new OrionVaultOptionsExtension Extension => (OrionVaultOptionsExtension)base.Extension;

        public override bool IsDatabaseProvider => false;

        public override string LogFragment => string.Empty;

        // Two option sets that wrap DIFFERENT inner factories must not share an internal service
        // provider, because ApplyServices registers a different concrete type into each.
        public override int GetServiceProviderHashCode() => Extension.InnerModelCacheKeyFactory?.GetHashCode() ?? 0;

        public override bool ShouldUseSameServiceProvider(DbContextOptionsExtensionInfo other)
            => other is ExtensionInfo o
                && o.Extension.InnerModelCacheKeyFactory == Extension.InnerModelCacheKeyFactory;

        public override void PopulateDebugInfo(IDictionary<string, string> debugInfo)
        {
            ArgumentNullException.ThrowIfNull(debugInfo);
            debugInfo["OrionVault:InnerModelCacheKeyFactory"] =
                Extension.InnerModelCacheKeyFactory?.FullName ?? "(EF Core default)";
        }
    }
}
