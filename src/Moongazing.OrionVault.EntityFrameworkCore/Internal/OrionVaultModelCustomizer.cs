namespace Moongazing.OrionVault.EntityFrameworkCore.Internal;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Moongazing.OrionVault.Abstractions;

internal sealed class OrionVaultModelCustomizer : IModelCustomizer
{
    private readonly IModelCustomizer _inner;
    private readonly IEncryptionConfigurator _configurator;

    public OrionVaultModelCustomizer(IModelCustomizer inner, IEncryptionConfigurator configurator)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(configurator);
        _inner = inner;
        _configurator = configurator;
    }

    public void Customize(ModelBuilder modelBuilder, DbContext context)
    {
        _inner.Customize(modelBuilder, context);
        _configurator.Configure(modelBuilder);
    }
}
