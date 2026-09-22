namespace Moongazing.OrionVault.Testing.DependencyInjection;

using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.Internal;

public static class OrionVaultTestingBuilderExtensions
{
    /// <summary>
    /// Register a complete OrionVault setup using <see cref="DangerousTestKeyProvider.Default"/>
    /// and the real AES-GCM encryptor. Use in tests instead of <c>AddOrionVault</c>.
    /// <para>
    /// The key is 32 zero bytes, so this throws unless the process opted in via
    /// <see cref="DangerousTestKeyProvider.Enable"/> or the matching AppContext switch.
    /// </para>
    /// </summary>
    public static OrionVaultBuilder AddOrionVaultForTesting(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<OrionVaultDiagnostics>();
#pragma warning disable OV9000 // the zero-key provider is the point of this test-only entry point
        services.AddSingleton<IKeyProvider>(DangerousTestKeyProvider.Default);
#pragma warning restore OV9000
        services.AddSingleton<IEncryptor, AesGcmEncryptor>();
        return new OrionVaultBuilder(services);
    }
}
