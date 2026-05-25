namespace Moongazing.OrionVault.DependencyInjection;

using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Returned from <see cref="OrionVaultServiceCollectionExtensions.AddOrionVault"/>.
/// Acts as a typed handle for chained registration extensions (UseEntityFrameworkCore,
/// UseTestKeys, etc.).
/// </summary>
public sealed class OrionVaultBuilder
{
    public OrionVaultBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    public IServiceCollection Services { get; }
}
