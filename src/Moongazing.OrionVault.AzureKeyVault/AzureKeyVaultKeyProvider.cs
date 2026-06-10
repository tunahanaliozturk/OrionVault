using System.Collections.Frozen;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Exceptions;

namespace Moongazing.OrionVault.AzureKeyVault;

/// <summary>
/// Azure Key Vault-backed <see cref="IKeyProvider"/>. Holds a map of OrionVault key ids to
/// the 32-byte plaintext data keys obtained by unwrapping the configured ciphertext blobs at
/// startup. The KEK never leaves Azure Key Vault; ciphertext blobs stored in OrionVault config
/// are useless without vault access.
/// </summary>
/// <remarks>
/// Multi-key read, single-key write rotation (same shape as <c>AwsKmsKeyProvider</c>): the
/// active id (<see cref="ActiveKeyId"/>) is used for new encryptions; previously-active ids
/// remain in the map until rows encrypted under them are re-encrypted by the v0.2.0
/// background re-encryption service. Each entry's plaintext is held in memory once and
/// reused; consumers MUST register the provider as singleton (the default
/// <c>AddOrionVaultAzureKeyVault</c> extension enforces this).
/// </remarks>
public sealed class AzureKeyVaultKeyProvider : IKeyProvider
{
    private readonly FrozenDictionary<short, ReadOnlyMemory<byte>> keys;

    /// <inheritdoc />
    public short ActiveKeyId { get; }

    /// <summary>
    /// Constructs the provider from a pre-built dictionary. Use the
    /// <see cref="CreateAsync"/> factory in production to unwrap the configured ciphertext
    /// blobs against Azure Key Vault; this constructor exists for tests and for advanced
    /// consumers that already hold the plaintext keys.
    /// </summary>
    public AzureKeyVaultKeyProvider(short activeKeyId, IDictionary<short, ReadOnlyMemory<byte>> plaintextKeys)
    {
        ArgumentNullException.ThrowIfNull(plaintextKeys);
        if (!plaintextKeys.ContainsKey(activeKeyId))
        {
            throw new OrionVaultConfigurationException(
                $"AzureKeyVaultKeyProvider: active key id {activeKeyId} is not in the supplied plaintext-key map. " +
                $"Registered ids: [{string.Join(", ", plaintextKeys.Keys)}].");
        }
        foreach (var (id, key) in plaintextKeys)
        {
            if (key.Length != 32)
            {
                throw new OrionVaultConfigurationException(
                    $"AzureKeyVaultKeyProvider: key id {id} length is {key.Length} bytes; OrionVault requires exactly 32.");
            }
        }
        ActiveKeyId = activeKeyId;
        keys = plaintextKeys.ToFrozenDictionary();
    }

    /// <inheritdoc />
    public ReadOnlyMemory<byte>? TryGetKey(short keyId)
        => keys.TryGetValue(keyId, out var key) ? (ReadOnlyMemory<byte>?)key : null;

    /// <summary>
    /// Unwraps each configured base64 ciphertext blob via the supplied
    /// <see cref="IKeyVaultUnwrapClient"/> and returns a ready-to-use provider. Call once at
    /// host startup. The vault calls run concurrently to keep startup fast.
    /// </summary>
    public static async Task<AzureKeyVaultKeyProvider> CreateAsync(
        IKeyVaultUnwrapClient unwrapClient,
        AzureKeyVaultKeyProviderOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(unwrapClient);
        ArgumentNullException.ThrowIfNull(options);
        if (options.WrappedKeys.Count == 0)
        {
            throw new OrionVaultConfigurationException(
                "AzureKeyVaultKeyProviderOptions.WrappedKeys is empty. At least one (keyId, ciphertextBase64) entry is required.");
        }
        if (string.IsNullOrWhiteSpace(options.KeyName))
        {
            throw new OrionVaultConfigurationException(
                "AzureKeyVaultKeyProviderOptions.KeyName must be a non-empty Key Vault key name or full key identifier.");
        }

        var tasks = options.WrappedKeys.Select(async pair =>
        {
            var (id, ciphertextBase64) = pair;
            if (string.IsNullOrWhiteSpace(ciphertextBase64))
            {
                throw new OrionVaultConfigurationException(
                    $"AzureKeyVaultKeyProvider: key id {id} ciphertext is null or whitespace.");
            }
            byte[] ciphertext;
            try
            {
                ciphertext = Convert.FromBase64String(ciphertextBase64);
            }
            catch (FormatException ex)
            {
                throw new OrionVaultConfigurationException(
                    $"AzureKeyVaultKeyProvider: key id {id} ciphertext is not valid base64.", ex);
            }
            if (ciphertext.Length == 0)
            {
                throw new OrionVaultConfigurationException(
                    $"AzureKeyVaultKeyProvider: key id {id} ciphertext decoded to zero bytes.");
            }

            var plaintext = await unwrapClient.UnwrapAsync(ciphertext, cancellationToken).ConfigureAwait(false);
            return (id, plaintext: (ReadOnlyMemory<byte>)plaintext);
        }).ToArray();

        var resolved = await Task.WhenAll(tasks).ConfigureAwait(false);
        var dict = resolved.ToDictionary(x => x.id, x => x.plaintext);
        return new AzureKeyVaultKeyProvider(options.ActiveKeyId, dict);
    }
}
