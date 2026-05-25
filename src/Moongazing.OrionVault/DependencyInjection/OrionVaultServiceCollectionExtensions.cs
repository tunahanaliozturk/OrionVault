namespace Moongazing.OrionVault.DependencyInjection;

using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.Exceptions;
using Moongazing.OrionVault.Internal;
using Moongazing.OrionVault.Options;

public static class OrionVaultServiceCollectionExtensions
{
    public static OrionVaultBuilder AddOrionVault(
        this IServiceCollection services,
        Action<OrionVaultOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new OrionVaultOptions();
        configure(options);

        var builder = options.KeysBuilder
            ?? throw new OrionVaultConfigurationException(
                "OrionVault requires at least one key. Call options.UseStaticKeys(...).");

        var keys = builder.Build();
        if (keys.Count == 0)
            throw new OrionVaultConfigurationException(
                "OrionVault requires at least one key. Call StaticKeysBuilder.Add(...).");
        if (!keys.ContainsKey(options.ActiveKeyId))
            throw new OrionVaultConfigurationException(
                $"ActiveKeyId {options.ActiveKeyId} is not registered. Registered ids: [{string.Join(", ", keys.Keys)}].");

        services.AddSingleton<IKeyProvider>(_ => new StaticKeyProvider(keys, options.ActiveKeyId));
        services.AddSingleton<OrionVaultDiagnostics>();
        services.AddSingleton<IEncryptor, AesGcmEncryptor>();

        return new OrionVaultBuilder(services);
    }
}
