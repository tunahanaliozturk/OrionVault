namespace Moongazing.OrionVault.GcpKms;

using Google.Cloud.Kms.V1;
using Google.Protobuf;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Caching;
using Moongazing.OrionVault.Exceptions;

/// <summary>
/// DI helpers for the Google Cloud KMS-backed <see cref="IKeyProvider"/>.
/// </summary>
public static class GcpKmsServiceCollectionExtensions
{
    /// <summary>
    /// Register <see cref="GcpKmsKeyProvider"/> as the singleton <see cref="IKeyProvider"/>.
    /// Consumers register the <see cref="KeyManagementServiceClient"/> themselves (e.g.
    /// <c>services.AddSingleton(KeyManagementServiceClient.Create())</c>) so the credentials and
    /// endpoint story stays in the consumer's hands.
    /// </summary>
    /// <remarks>
    /// CAUTION: on the default (unwrap-once) path the factory blocks during host startup while it
    /// round-trips the configured ciphertext blobs through Cloud KMS. Typical latency is one
    /// round-trip per key id. The decrypted plaintext keys live in process memory for the
    /// provider lifetime; OrionVault does NOT cache plaintext anywhere else.
    /// <para>
    /// When <see cref="EnvelopeKeyCacheOptions.Enabled"/> is set on
    /// <see cref="GcpKmsKeyProviderOptions.Cache"/>, the provider is wrapped in a
    /// <see cref="CachingKeyProvider"/> that re-fetches the wrapped keys after the configured TTL,
    /// so a Cloud KMS key disabled / rotated mid-run is honoured without a host restart.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddOrionVaultGcpKms(
        this IServiceCollection services,
        Action<GcpKmsKeyProviderOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);

        services.AddSingleton<IKeyProvider>(sp =>
        {
            var opts = sp.GetRequiredService<IOptions<GcpKmsKeyProviderOptions>>().Value;
            var kms = sp.GetRequiredService<KeyManagementServiceClient>();

            // Validate the crypto-key resource name before building the adapter so a malformed name
            // fails fast at composition with a clear OrionVault error rather than deeper in the SDK.
            if (string.IsNullOrWhiteSpace(opts.CryptoKeyName) || !CryptoKeyName.TryParse(opts.CryptoKeyName, out _))
            {
                throw new OrionVaultConfigurationException(
                    "GcpKmsKeyProviderOptions.CryptoKeyName must be a valid Cloud KMS crypto-key resource name, " +
                    "e.g. projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}; got " +
                    $"'{opts.CryptoKeyName}'.");
            }

            var decryptClient = new KeyManagementServiceDecryptAdapter(kms);

            if (opts.Cache.Enabled)
            {
                opts.Cache.Validate();
                var source = GcpKmsKeyProvider.CreateUnwrappedKeySource(decryptClient, opts);
                var caching = new CachingKeyProvider(source, opts.Cache, sp.GetService<TimeProvider>());
                // Prime up front so misconfiguration / first KMS round-trip surfaces at startup,
                // matching the unwrap-once path's fail-fast behaviour.
                caching.Prime();
                return caching;
            }

            return GcpKmsKeyProvider.CreateAsync(decryptClient, opts).GetAwaiter().GetResult();
        });

        return services;
    }

    private sealed class KeyManagementServiceDecryptAdapter : IGcpKmsDecryptClient
    {
        private readonly KeyManagementServiceClient client;

        public KeyManagementServiceDecryptAdapter(KeyManagementServiceClient client)
            => this.client = client;

        public async Task<byte[]> DecryptAsync(string cryptoKeyName, byte[] ciphertext, CancellationToken cancellationToken)
        {
            // Decrypt under the crypto-key name supplied by the caller (the validated options value),
            // so the same name the provider validated is the one KMS decrypts under.
            var response = await client.DecryptAsync(
                CryptoKeyName.Parse(cryptoKeyName),
                ByteString.CopyFrom(ciphertext),
                cancellationToken).ConfigureAwait(false);
            return response.Plaintext.ToByteArray();
        }
    }
}
