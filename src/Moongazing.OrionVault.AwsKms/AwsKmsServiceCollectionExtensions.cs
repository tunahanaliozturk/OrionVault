namespace Moongazing.OrionVault.AwsKms;

using Amazon.KeyManagementService;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moongazing.OrionVault.Abstractions;

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
    /// CAUTION: the factory blocks during host startup while it round-trips the configured
    /// ciphertext blobs through AWS KMS. Typical latency is one round-trip per key id
    /// (usually only a couple). The decrypted plaintext keys live in process memory for the
    /// lifetime of the provider; OrionVault does NOT cache plaintext anywhere else.
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
            return AwsKmsKeyProvider.CreateAsync(kms, opts).GetAwaiter().GetResult();
        });

        return services;
    }
}
