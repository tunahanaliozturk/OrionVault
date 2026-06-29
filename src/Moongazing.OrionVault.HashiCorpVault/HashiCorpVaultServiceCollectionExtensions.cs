namespace Moongazing.OrionVault.HashiCorpVault;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Caching;
using Moongazing.OrionVault.Exceptions;
using VaultSharp;
using VaultSharp.V1.SecretsEngines.Transit;

/// <summary>
/// DI helpers for the HashiCorp Vault transit-engine-backed <see cref="IKeyProvider"/>.
/// </summary>
public static class HashiCorpVaultServiceCollectionExtensions
{
    /// <summary>
    /// Register <see cref="HashiCorpVaultKeyProvider"/> as the singleton <see cref="IKeyProvider"/>.
    /// Consumers register the <see cref="IVaultClient"/> themselves (e.g.
    /// <c>services.AddSingleton&lt;IVaultClient&gt;(new VaultClient(settings))</c>) so the auth
    /// method and endpoint story stays in the consumer's hands.
    /// </summary>
    /// <remarks>
    /// CAUTION: on the default (unwrap-once) path the factory blocks during host startup while it
    /// round-trips the configured transit ciphertext strings through Vault. Typical latency is one
    /// round-trip per key id. The decrypted plaintext keys live in process memory for the provider
    /// lifetime; OrionVault does NOT cache plaintext anywhere else.
    /// <para>
    /// When <see cref="EnvelopeKeyCacheOptions.Enabled"/> is set on
    /// <see cref="HashiCorpVaultKeyProviderOptions.Cache"/>, the provider is wrapped in a
    /// <see cref="CachingKeyProvider"/> that re-fetches the wrapped keys after the configured TTL,
    /// so a transit key rotated / disabled mid-run is honoured without a host restart.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddOrionVaultHashiCorpVault(
        this IServiceCollection services,
        Action<HashiCorpVaultKeyProviderOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);

        services.AddSingleton<IKeyProvider>(sp =>
        {
            var opts = sp.GetRequiredService<IOptions<HashiCorpVaultKeyProviderOptions>>().Value;
            var vault = sp.GetRequiredService<IVaultClient>();

            // Validate the transit key name before building the adapter so a blank name fails fast at
            // composition with a clear OrionVault error rather than deeper in the Vault round-trip.
            if (string.IsNullOrWhiteSpace(opts.TransitKeyName))
            {
                throw new OrionVaultConfigurationException(
                    "HashiCorpVaultKeyProviderOptions.TransitKeyName must be a non-empty Vault transit key name.");
            }

            var decryptClient = new VaultTransitDecryptAdapter(vault, opts.TransitKeyName, opts.MountPoint);

            if (opts.Cache.Enabled)
            {
                opts.Cache.Validate();
                var source = HashiCorpVaultKeyProvider.CreateUnwrappedKeySource(decryptClient, opts);
                var caching = new CachingKeyProvider(source, opts.Cache, sp.GetService<TimeProvider>());
                caching.Prime();
                return caching;
            }

            return HashiCorpVaultKeyProvider.CreateAsync(decryptClient, opts).GetAwaiter().GetResult();
        });

        return services;
    }

    private sealed class VaultTransitDecryptAdapter : IVaultTransitDecryptClient
    {
        private readonly IVaultClient client;
        private readonly string transitKeyName;
        private readonly string mountPoint;

        public VaultTransitDecryptAdapter(IVaultClient client, string transitKeyName, string mountPoint)
        {
            this.client = client;
            this.transitKeyName = transitKeyName;
            this.mountPoint = string.IsNullOrWhiteSpace(mountPoint) ? "transit" : mountPoint;
        }

        public async Task<byte[]> DecryptAsync(string ciphertext, CancellationToken cancellationToken)
        {
            // The transit decrypt endpoint takes a (single-item) batch and returns base64-encoded
            // plaintext per item. VaultSharp does not surface a CancellationToken on this call;
            // honour cancellation cooperatively before dispatching.
            cancellationToken.ThrowIfCancellationRequested();

            var options = new DecryptRequestOptions
            {
                BatchedDecryptionItems = new List<DecryptionItem>
                {
                    new() { CipherText = ciphertext },
                },
            };

            var response = await client.V1.Secrets.Transit
                .DecryptAsync(transitKeyName, options, mountPoint)
                .ConfigureAwait(false);

            var first = response?.Data?.BatchedResults?.FirstOrDefault()
                ?? throw new InvalidOperationException(
                    "Vault transit decrypt returned no batch result for the supplied ciphertext.");

            return Convert.FromBase64String(first.Base64EncodedPlainText);
        }
    }
}
