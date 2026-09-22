namespace Moongazing.OrionVault.AwsKms;

using Amazon.KeyManagementService;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Caching;
using Moongazing.OrionVault.Exceptions;

/// <summary>
/// DI helpers for the AWS KMS-backed <see cref="IKeyProvider"/>.
/// </summary>
public static class AwsKmsServiceCollectionExtensions
{
    /// <summary>
    /// Register <see cref="AwsKmsKeyProvider"/> as the singleton <see cref="IKeyProvider"/>.
    /// The factory calls <see cref="AwsKmsKeyProvider.CreateAsync"/> once with the supplied
    /// <see cref="IAmazonKeyManagementService"/> (resolved from DI). Consumers register the
    /// KMS client themselves via <c>services.AddAWSService&lt;IAmazonKeyManagementService&gt;()</c>
    /// or any other DI shape they prefer.
    /// </summary>
    /// <remarks>
    /// <see cref="AwsKmsKeyProviderOptions.KeyId"/> is required and is validated here so a
    /// deployment that forgot to pin its CMK fails at composition rather than decrypting a
    /// substituted blob.
    /// <para>
    /// CAUTION: on the default (unwrap-once) path the factory blocks during host startup while
    /// it round-trips the configured ciphertext blobs through AWS KMS. Typical latency is one
    /// round-trip per key id (usually only a couple). The decrypted plaintext keys live in
    /// process memory for the lifetime of the provider; OrionVault does NOT cache plaintext
    /// anywhere else.
    /// </para>
    /// <para>
    /// When <see cref="EnvelopeKeyCacheOptions.Enabled"/> is set on
    /// <see cref="AwsKmsKeyProviderOptions.Cache"/>, the provider is wrapped in a
    /// <see cref="CachingKeyProvider"/> that re-fetches the wrapped keys after the configured TTL,
    /// so a CMK disabled / scheduled for deletion / access-withdrawn mid-run is honoured without
    /// a host restart.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddOrionVaultAwsKms(
        this IServiceCollection services,
        Action<AwsKmsKeyProviderOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);
        services.AddSingleton<IKeyProvider>(sp =>
        {
            var kms = sp.GetRequiredService<IAmazonKeyManagementService>();
            // Resolve via IOptions so any additional Configure<>/PostConfigure<> registrations
            // (test overrides, layered config sources, named-options, etc.) are honoured
            // instead of being silently bypassed.
            var opts = sp.GetRequiredService<IOptions<AwsKmsKeyProviderOptions>>().Value;

            if (string.IsNullOrWhiteSpace(opts.KeyId))
            {
                throw new OrionVaultConfigurationException(
                    "AwsKmsKeyProviderOptions.KeyId must be set to the AWS KMS customer master key " +
                    "(key id, key ARN, alias name or alias ARN) the wrapped data keys were encrypted " +
                    "under. Every decrypt is pinned to it so a ciphertext blob substituted into " +
                    "WrappedKeys cannot be decrypted under some other CMK the host happens to have " +
                    "kms:Decrypt on.");
            }

            if (opts.Cache.Enabled)
            {
                opts.Cache.Validate();
                var source = AwsKmsKeyProvider.CreateUnwrappedKeySource(kms, opts);
                var caching = new CachingKeyProvider(source, opts.Cache, sp.GetService<TimeProvider>());
                // Prime up front so misconfiguration / first KMS round-trip surfaces at startup,
                // matching the unwrap-once path's fail-fast behaviour.
                caching.Prime();
                return caching;
            }

            return AwsKmsKeyProvider.CreateAsync(kms, opts).GetAwaiter().GetResult();
        });

        return services;
    }
}
