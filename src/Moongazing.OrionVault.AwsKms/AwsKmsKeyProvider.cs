namespace Moongazing.OrionVault.AwsKms;

using System.Collections.Frozen;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Exceptions;

/// <summary>
/// AWS KMS-backed <see cref="IKeyProvider"/>. Holds a map of OrionVault key ids to the
/// 32-byte plaintext data keys obtained by decrypting the configured KMS ciphertext blobs at
/// startup. The CMK never leaves AWS; ciphertext blobs stored in OrionVault config / source
/// control are useless without the AWS account.
/// </summary>
/// <remarks>
/// Multi-key read, single-key write rotation: the active id (<see cref="ActiveKeyId"/>) is
/// used for new encryptions; previously-active ids remain in the map until rows encrypted
/// under them are re-encrypted by the v0.2.0 background re-encryption service. Each entry's
/// plaintext is held in memory once and reused; consumers MUST register the provider as
/// singleton (the default <c>AddOrionVaultAwsKms</c> extension enforces this).
/// </remarks>
public sealed class AwsKmsKeyProvider : IKeyProvider
{
    private readonly FrozenDictionary<short, ReadOnlyMemory<byte>> keys;

    /// <inheritdoc />
    public short ActiveKeyId { get; }

    /// <summary>
    /// Constructs the provider from a pre-built dictionary. Use the
    /// <see cref="CreateAsync"/> factory in production to decrypt the configured ciphertext
    /// blobs against AWS KMS; this constructor exists for tests and for advanced consumers
    /// that already hold the plaintext keys.
    /// </summary>
    public AwsKmsKeyProvider(short activeKeyId, IDictionary<short, ReadOnlyMemory<byte>> plaintextKeys)
    {
        ArgumentNullException.ThrowIfNull(plaintextKeys);
        if (!plaintextKeys.ContainsKey(activeKeyId))
        {
            throw new OrionVaultConfigurationException(
                $"AwsKmsKeyProvider: active key id {activeKeyId} is not in the supplied plaintext-key map. " +
                $"Registered ids: [{string.Join(", ", plaintextKeys.Keys)}].");
        }
        foreach (var (id, key) in plaintextKeys)
        {
            if (key.Length != 32)
            {
                throw new OrionVaultConfigurationException(
                    $"AwsKmsKeyProvider: key id {id} length is {key.Length} bytes; OrionVault requires exactly 32.");
            }
        }
        ActiveKeyId = activeKeyId;
        keys = plaintextKeys.ToFrozenDictionary();
    }

    /// <inheritdoc />
    public ReadOnlyMemory<byte>? TryGetKey(short keyId)
        => keys.TryGetValue(keyId, out var key) ? (ReadOnlyMemory<byte>?)key : null;

    /// <summary>
    /// Decrypts each configured base64 ciphertext blob via the supplied
    /// <see cref="IAmazonKeyManagementService"/> client and returns a ready-to-use provider.
    /// Call once at host startup. The KMS API calls run concurrently to keep startup fast.
    /// </summary>
    public static async Task<AwsKmsKeyProvider> CreateAsync(
        IAmazonKeyManagementService kms,
        AwsKmsKeyProviderOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(kms);
        ArgumentNullException.ThrowIfNull(options);
        if (options.WrappedKeys.Count == 0)
        {
            throw new OrionVaultConfigurationException(
                "AwsKmsKeyProviderOptions.WrappedKeys is empty. At least one (keyId, ciphertextBase64) entry is required.");
        }

        var tasks = options.WrappedKeys.Select(async pair =>
        {
            var (id, ciphertextBase64) = pair;
            byte[] ciphertext;
            try
            {
                ciphertext = Convert.FromBase64String(ciphertextBase64);
            }
            catch (FormatException ex)
            {
                throw new OrionVaultConfigurationException(
                    $"AwsKmsKeyProvider: key id {id} ciphertext is not valid base64.", ex);
            }

            using var stream = new MemoryStream(ciphertext);
            var response = await kms.DecryptAsync(
                new DecryptRequest { CiphertextBlob = stream },
                cancellationToken).ConfigureAwait(false);
            return (id, plaintext: (ReadOnlyMemory<byte>)response.Plaintext.ToArray());
        }).ToArray();

        var resolved = await Task.WhenAll(tasks).ConfigureAwait(false);
        var dict = resolved.ToDictionary(x => x.id, x => x.plaintext);
        return new AwsKmsKeyProvider(options.ActiveKeyId, dict);
    }
}
