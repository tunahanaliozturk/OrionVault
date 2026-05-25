namespace Moongazing.OrionVault.EntityFrameworkCore.Internal;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;

internal sealed class OrionVaultModelCustomizer : IModelCustomizer
{
    // The inner customizer is constructed manually, NOT injected. EF Core resolves
    // OrionVaultModelCustomizer through its own internal service provider when wired via
    // ReplaceService<IModelCustomizer, OrionVaultModelCustomizer>; that internal SP does NOT
    // expose application-side registrations as injectable constructor parameters, so accepting
    // IEncryptionConfigurator here would fail with "Unable to resolve" at first model build.
    // Instead we look the configurator up from the live DbContext on each Customize call —
    // DbContext.GetService<T>() falls through EF Core's internal SP to the application SP
    // attached via UseApplicationServiceProvider, where IEncryptionConfigurator is registered
    // by UseEntityFrameworkCore<TDbContext>.
    private readonly ModelCustomizer _inner;

#pragma warning disable EF1001 // Internal EF Core API: ModelCustomizerDependencies (record-style dep bag, parameterless ctor)
    public OrionVaultModelCustomizer()
    {
        _inner = new ModelCustomizer(new ModelCustomizerDependencies());
    }
#pragma warning restore EF1001

    public void Customize(ModelBuilder modelBuilder, DbContext context)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        ArgumentNullException.ThrowIfNull(context);

        _inner.Customize(modelBuilder, context);

        var configurator = context.GetService<IEncryptionConfigurator>();
        configurator.Configure(modelBuilder);
    }
}
