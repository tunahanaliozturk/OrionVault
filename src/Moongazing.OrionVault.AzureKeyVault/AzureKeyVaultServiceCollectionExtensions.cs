using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moongazing.OrionVault.Abstractions;

namespace Moongazing.OrionVault.AzureKeyVault;

/// <summary>
/// DI helpers for the Azure Key Vault-backed <see cref="IKeyProvider"/>.
/// </summary>
public static class AzureKeyVaultServiceCollectionExtensions
{
    /// <summary>
    /// Register <see cref="AzureKeyVaultKeyProvider"/> as the singleton
    /// <see cref="IKeyProvider"/>. Consumers register the <see cref="KeyClient"/> themselves
    /// (e.g., <c>services.AddSingleton(new KeyClient(new Uri(...), new DefaultAzureCredential()))</c>)
    /// so the credentials story stays in the consumer's hands.
    /// </summary>
    /// <remarks>
    /// CAUTION: the factory blocks during host startup while it round-trips the configured
    /// ciphertext blobs through Azure Key Vault. Typical latency is one round-trip per key id.
    /// The unwrapped plaintext data keys live in process memory for the provider lifetime;
    /// OrionVault does NOT cache plaintext anywhere else.
    /// </remarks>
    public static IServiceCollection AddOrionVaultAzureKeyVault(
        this IServiceCollection services,
        Action<AzureKeyVaultKeyProviderOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);

        services.AddSingleton<IKeyProvider>(sp =>
        {
            var keyClient = sp.GetRequiredService<KeyClient>();
            var opts = sp.GetRequiredService<IOptions<AzureKeyVaultKeyProviderOptions>>().Value;
            var cryptoClient = string.IsNullOrEmpty(opts.KeyVersion)
                ? keyClient.GetCryptographyClient(opts.KeyName)
                : keyClient.GetCryptographyClient(opts.KeyName, opts.KeyVersion);
            var unwrapClient = new CryptographyClientUnwrapAdapter(cryptoClient, opts.WrapAlgorithm);
            return AzureKeyVaultKeyProvider.CreateAsync(unwrapClient, opts).GetAwaiter().GetResult();
        });

        return services;
    }

    private sealed class CryptographyClientUnwrapAdapter : IKeyVaultUnwrapClient
    {
        private readonly CryptographyClient client;
        private readonly KeyWrapAlgorithm algorithm;

        public CryptographyClientUnwrapAdapter(CryptographyClient client, KeyWrapAlgorithm algorithm)
        {
            this.client = client;
            this.algorithm = algorithm;
        }

        public async Task<byte[]> UnwrapAsync(byte[] encryptedKey, CancellationToken cancellationToken)
        {
            var response = await client.UnwrapKeyAsync(algorithm, encryptedKey, cancellationToken).ConfigureAwait(false);
            return response.Key;
        }
    }
}
