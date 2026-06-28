namespace Moongazing.OrionVault.GcpKms;

using System.Collections.Frozen;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Exceptions;

/// <summary>
/// Google Cloud KMS-backed <see cref="IKeyProvider"/>. Holds a map of OrionVault key ids to the
/// 32-byte plaintext data keys obtained by decrypting the configured KMS ciphertext blobs at
/// startup. The Cloud KMS key never leaves Google Cloud; ciphertext blobs stored in OrionVault
/// config / source control are useless without project access.
/// </summary>
/// <remarks>
/// Multi-key read, single-key write rotation (same shape as <c>AwsKmsKeyProvider</c>): the active
/// id (<see cref="ActiveKeyId"/>) is used for new encryptions; previously-active ids remain in the
/// map until rows encrypted under them are re-encrypted by the v0.2.0 background re-encryption
/// service. Each entry's plaintext is held in memory once and reused; consumers MUST register the
/// provider as singleton (the default <c>AddOrionVaultGcpKms</c> extension enforces this).
/// </remarks>
public sealed class GcpKmsKeyProvider : IKeyProvider, IUnwrappedKeySource
{
    private readonly FrozenDictionary<short, ReadOnlyMemory<byte>> keys;

    /// <inheritdoc />
    public short ActiveKeyId { get; }

    /// <summary>
    /// Constructs the provider from a pre-built dictionary. Use the <see cref="CreateAsync"/>
    /// factory in production to decrypt the configured ciphertext blobs against Cloud KMS; this
    /// constructor exists for tests and for advanced consumers that already hold the plaintext
    /// keys.
    /// </summary>
    public GcpKmsKeyProvider(short activeKeyId, IDictionary<short, ReadOnlyMemory<byte>> plaintextKeys)
    {
        ArgumentNullException.ThrowIfNull(plaintextKeys);
        if (!plaintextKeys.ContainsKey(activeKeyId))
        {
            throw new OrionVaultConfigurationException(
                $"GcpKmsKeyProvider: active key id {activeKeyId} is not in the supplied plaintext-key map. " +
                $"Registered ids: [{string.Join(", ", plaintextKeys.Keys)}].");
        }
        foreach (var (id, key) in plaintextKeys)
        {
            if (key.Length != 32)
            {
                throw new OrionVaultConfigurationException(
                    $"GcpKmsKeyProvider: key id {id} length is {key.Length} bytes; OrionVault requires exactly 32.");
            }
        }
        ActiveKeyId = activeKeyId;
        keys = plaintextKeys.ToFrozenDictionary();
    }

    /// <inheritdoc />
    public ReadOnlyMemory<byte>? TryGetKey(short keyId)
        => keys.TryGetValue(keyId, out var key) ? (ReadOnlyMemory<byte>?)key : null;

    /// <inheritdoc />
    public int KeyCount => keys.Count;

    /// <summary>
    /// Decrypts each configured base64 ciphertext blob via the supplied
    /// <see cref="IGcpKmsDecryptClient"/> and returns a ready-to-use provider. Call once at host
    /// startup. The KMS calls run concurrently to keep startup fast.
    /// </summary>
    public static async Task<GcpKmsKeyProvider> CreateAsync(
        IGcpKmsDecryptClient decryptClient,
        GcpKmsKeyProviderOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(decryptClient);
        ArgumentNullException.ThrowIfNull(options);

        var unwrapped = await UnwrapAllAsync(decryptClient, options, cancellationToken).ConfigureAwait(false);
        var map = unwrapped.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        return new GcpKmsKeyProvider(options.ActiveKeyId, map);
    }

    /// <summary>
    /// Decodes and decrypts every configured ciphertext entry. Shared by <see cref="CreateAsync"/>
    /// (unwrap-once) and the envelope-key cache refresh path so both go through identical
    /// validation. Static so it is callable before an instance exists.
    /// </summary>
    internal static async Task<IReadOnlyDictionary<short, ReadOnlyMemory<byte>>> UnwrapAllAsync(
        IGcpKmsDecryptClient decryptClient,
        GcpKmsKeyProviderOptions options,
        CancellationToken cancellationToken)
    {
        if (options.WrappedKeys.Count == 0)
        {
            throw new OrionVaultConfigurationException(
                "GcpKmsKeyProviderOptions.WrappedKeys is empty. At least one (keyId, ciphertextBase64) entry is required.");
        }
        if (string.IsNullOrWhiteSpace(options.CryptoKeyName))
        {
            throw new OrionVaultConfigurationException(
                "GcpKmsKeyProviderOptions.CryptoKeyName must be a non-empty Cloud KMS crypto-key resource name.");
        }

        var tasks = options.WrappedKeys.Select(async pair =>
        {
            var (id, ciphertextBase64) = pair;
            if (string.IsNullOrWhiteSpace(ciphertextBase64))
            {
                throw new OrionVaultConfigurationException(
                    $"GcpKmsKeyProvider: key id {id} ciphertext is null or whitespace.");
            }
            byte[] ciphertext;
            try
            {
                ciphertext = Convert.FromBase64String(ciphertextBase64);
            }
            catch (FormatException ex)
            {
                throw new OrionVaultConfigurationException(
                    $"GcpKmsKeyProvider: key id {id} ciphertext is not valid base64.", ex);
            }
            if (ciphertext.Length == 0)
            {
                throw new OrionVaultConfigurationException(
                    $"GcpKmsKeyProvider: key id {id} ciphertext decoded to zero bytes.");
            }

            var plaintext = await decryptClient.DecryptAsync(ciphertext, cancellationToken).ConfigureAwait(false);
            return (id, plaintext: (ReadOnlyMemory<byte>)plaintext);
        }).ToArray();

        var resolved = await Task.WhenAll(tasks).ConfigureAwait(false);
        return resolved.ToDictionary(x => x.id, x => x.plaintext);
    }

    /// <summary>
    /// Adapts a configured provider + decrypt client into an <see cref="IUnwrappedKeySource"/> the
    /// core <see cref="Moongazing.OrionVault.Caching.CachingKeyProvider"/> refreshes against. Used
    /// only on the opt-in caching path; the unwrap-once path never touches this.
    /// </summary>
    public static IUnwrappedKeySource CreateUnwrappedKeySource(
        IGcpKmsDecryptClient decryptClient,
        GcpKmsKeyProviderOptions options)
        => new UnwrappedKeySource(decryptClient, options);

    Task<IReadOnlyDictionary<short, ReadOnlyMemory<byte>>> IUnwrappedKeySource.UnwrapAllAsync(
        CancellationToken cancellationToken)
        => Task.FromResult<IReadOnlyDictionary<short, ReadOnlyMemory<byte>>>(
            keys.ToDictionary(kvp => kvp.Key, kvp => kvp.Value));

    private sealed class UnwrappedKeySource : IUnwrappedKeySource
    {
        private readonly IGcpKmsDecryptClient decryptClient;
        private readonly GcpKmsKeyProviderOptions options;

        public UnwrappedKeySource(IGcpKmsDecryptClient decryptClient, GcpKmsKeyProviderOptions options)
        {
            this.decryptClient = decryptClient;
            this.options = options;
        }

        public short ActiveKeyId => options.ActiveKeyId;

        public Task<IReadOnlyDictionary<short, ReadOnlyMemory<byte>>> UnwrapAllAsync(
            CancellationToken cancellationToken)
            => GcpKmsKeyProvider.UnwrapAllAsync(decryptClient, options, cancellationToken);
    }
}
