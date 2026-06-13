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
        // v0.2.22: wire the active-key-id gauge snapshot at construction time so the
        // orionvault.active_key_id observable gauge reports the configured value from
        // the moment the host starts emitting metrics.
        services.AddSingleton<OrionVaultDiagnostics>(_ =>
        {
            var diag = new OrionVaultDiagnostics();
            diag.SetActiveKeyIdSnapshot(options.ActiveKeyId);
            return diag;
        });
        // v0.2.23: explicit ctor invocation so optional hooks (IDecryptionFailureHandler,
        // IEncryptionAuditObserver) are wired independently. ActivatorUtilities longest-
        // ctor pick would silently drop one hook when only the other is registered -
        // same trap as the v0.2.20 OrionPatch P1.
        services.AddSingleton<IEncryptor>(sp =>
        {
            var keys = sp.GetRequiredService<IKeyProvider>();
            var diag = sp.GetRequiredService<Diagnostics.OrionVaultDiagnostics>();
            // v0.2.25: snapshot the provider's registered key count for the
            // orionvault.keys.registered_count gauge. -1 = provider cannot enumerate.
            diag.SetRegisteredKeyCountSnapshot(keys.KeyCount);
            return new Internal.AesGcmEncryptor(
                keys,
                diag,
                sp.GetService<IDecryptionFailureHandler>(),
                sp.GetService<IEncryptionAuditObserver>());
        });

        return new OrionVaultBuilder(services);
    }
}
