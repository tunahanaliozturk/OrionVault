namespace Moongazing.OrionVault.GcpKms;

using Google.Cloud.Kms.V1;
using Google.Protobuf;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Caching;

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
            var decryptClient = new KeyManagementServiceDecryptAdapter(kms, opts.CryptoKeyName);

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
        private readonly CryptoKeyName cryptoKeyName;

        public KeyManagementServiceDecryptAdapter(KeyManagementServiceClient client, string cryptoKeyName)
        {
            this.client = client;
            // Parsed once; an invalid resource name fails fast here rather than per decrypt call.
            this.cryptoKeyName = CryptoKeyName.Parse(cryptoKeyName);
        }

        public async Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken cancellationToken)
        {
            var response = await client.DecryptAsync(
                cryptoKeyName,
                ByteString.CopyFrom(ciphertext),
                cancellationToken).ConfigureAwait(false);
            return response.Plaintext.ToByteArray();
        }
    }
}
