namespace Moongazing.OrionVault.DependencyInjection;

using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.BlindIndex;
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
        services.AddSingleton<IEncryptor>(sp => new Internal.AesGcmEncryptor(
            sp.GetRequiredService<IKeyProvider>(),
            sp.GetRequiredService<Diagnostics.OrionVaultDiagnostics>(),
            sp.GetService<IDecryptionFailureHandler>(),
            sp.GetService<IEncryptionAuditObserver>()));
        // v0.2.25 (codex P2): the registered-key-count snapshot now happens inside the
        // AesGcmEncryptor ctor so EVERY construction path (DI, keyed-provider factory,
        // public factory) populates the gauge - not just this DI registration.

        // v0.3.0: searchable encryption (blind index). Opt-in - only registered when the caller
        // supplied index keys via options.UseBlindIndex(...). Validated here at startup, mirroring
        // the encryption-key validation above, so a misconfigured ActiveBlindIndexVersion fails
        // fast rather than at first write.
        if (options.BlindIndexKeysBuilder is { } indexKeysBuilder)
        {
            var indexKeys = indexKeysBuilder.Build();
            if (indexKeys.Count == 0)
                throw new OrionVaultConfigurationException(
                    "UseBlindIndex was called but no index key was added. Call BlindIndexKeysBuilder.Add(...).");
            if (!indexKeys.ContainsKey(options.ActiveBlindIndexVersion))
                throw new OrionVaultConfigurationException(
                    $"ActiveBlindIndexVersion {options.ActiveBlindIndexVersion} is not registered. Registered versions: [{string.Join(", ", indexKeys.Keys)}].");

            var activeVersion = options.ActiveBlindIndexVersion;
            var normalization = options.BlindIndexNormalization;
            services.AddSingleton<IBlindIndexProvider>(
                _ => new HmacBlindIndexProvider(indexKeys, activeVersion, normalization));
        }

        return new OrionVaultBuilder(services);
    }
}
