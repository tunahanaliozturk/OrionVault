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
/// <para>
/// Every decrypt is pinned to <see cref="AwsKmsKeyProviderOptions.KeyId"/>, so a substituted
/// ciphertext blob wrapped under some other CMK is rejected by KMS instead of silently
/// becoming the active data key.
/// </para>
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

        var unwrapped = await UnwrapAllAsync(kms, options, cancellationToken).ConfigureAwait(false);
        var map = unwrapped.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        return new AwsKmsKeyProvider(options.ActiveKeyId, map);
    }

    /// <summary>
    /// Decodes and decrypts every configured ciphertext entry against the validated
    /// <see cref="AwsKmsKeyProviderOptions.KeyId"/>. Shared by <see cref="CreateAsync"/>
    /// (unwrap-once) and the envelope-key cache refresh path so both go through identical
    /// validation and both decrypt under the exact configured CMK. Static so it is callable
    /// before an instance exists.
    /// </summary>
    internal static async Task<IReadOnlyDictionary<short, ReadOnlyMemory<byte>>> UnwrapAllAsync(
        IAmazonKeyManagementService kms,
        AwsKmsKeyProviderOptions options,
        CancellationToken cancellationToken)
    {
        if (options.WrappedKeys.Count == 0)
        {
            throw new OrionVaultConfigurationException(
                "AwsKmsKeyProviderOptions.WrappedKeys is empty. At least one (keyId, ciphertextBase64) entry is required.");
        }
        if (string.IsNullOrWhiteSpace(options.KeyId))
        {
            throw new OrionVaultConfigurationException(
                "AwsKmsKeyProviderOptions.KeyId must be a non-empty AWS KMS customer master key id, key ARN, " +
                "alias name or alias ARN. It is required: the provider pins every decrypt to this CMK so a " +
                "substituted ciphertext blob wrapped under a different key cannot become the active data key.");
        }

        var cmk = options.KeyId;
        var tasks = options.WrappedKeys.Select(async pair =>
        {
            var (id, ciphertextBase64) = pair;
            if (string.IsNullOrWhiteSpace(ciphertextBase64))
            {
                throw new OrionVaultConfigurationException(
                    $"AwsKmsKeyProvider: key id {id} ciphertext is null or whitespace.");
            }
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
            if (ciphertext.Length == 0)
            {
                throw new OrionVaultConfigurationException(
                    $"AwsKmsKeyProvider: key id {id} ciphertext decoded to zero bytes.");
            }

            using var stream = new MemoryStream(ciphertext);
            // KeyId pins the decrypt to the configured CMK. Omitting it lets KMS resolve the key
            // from the blob's own metadata, which is what makes a substituted blob dangerous.
            var response = await kms.DecryptAsync(
                new DecryptRequest { CiphertextBlob = stream, KeyId = cmk },
                cancellationToken).ConfigureAwait(false);
            return (id, plaintext: (ReadOnlyMemory<byte>)response.Plaintext.ToArray());
        }).ToArray();

        var resolved = await Task.WhenAll(tasks).ConfigureAwait(false);
        return resolved.ToDictionary(x => x.id, x => x.plaintext);
    }

}
