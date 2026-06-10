namespace Moongazing.OrionVault.EntityFrameworkCore;

using Microsoft.EntityFrameworkCore;

/// <summary>
/// Per-DbContext binding between a <typeparamref name="TDbContext"/> and a named
/// <c>IEncryptionConfigurator</c> registered under <see cref="ProviderName"/>. Registered
/// as a singleton via <c>services.AddSingleton(new KeyedOrionVaultBinding&lt;Db&gt;("name"))</c>
/// and read by <see cref="KeyedOrionVaultModelCustomizer{TDbContext}"/> on each model
/// build. The binding type is generic so two DbContexts can resolve to different
/// providers without colliding in DI.
/// </summary>
/// <typeparam name="TDbContext">The DbContext the binding scopes.</typeparam>
public sealed class KeyedOrionVaultBinding<TDbContext>
    where TDbContext : DbContext
{
    /// <summary>Construct with the keyed-provider name (must match the value used in <c>UseEntityFrameworkCore&lt;TDbContext&gt;(name)</c>).</summary>
    public KeyedOrionVaultBinding(string providerName)
    {
        ArgumentException.ThrowIfNullOrEmpty(providerName);
        ProviderName = providerName;
    }

    /// <summary>Keyed name of the IEncryptionConfigurator to apply on the DbContext's model.</summary>
    public string ProviderName { get; }
}
