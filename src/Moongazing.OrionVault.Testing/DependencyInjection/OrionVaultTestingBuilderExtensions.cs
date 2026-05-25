namespace Moongazing.OrionVault.Testing.DependencyInjection;

using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.Internal;

public static class OrionVaultTestingBuilderExtensions
{
    /// <summary>
    /// Register a complete OrionVault setup using <see cref="TestKeyProvider.Default"/>
    /// and the real AES-GCM encryptor. Use in tests instead of <c>AddOrionVault</c>.
    /// </summary>
    public static OrionVaultBuilder AddOrionVaultForTesting(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<OrionVaultDiagnostics>();
        services.AddSingleton<IKeyProvider>(TestKeyProvider.Default);
        services.AddSingleton<IEncryptor, AesGcmEncryptor>();
        return new OrionVaultBuilder(services);
    }
}
