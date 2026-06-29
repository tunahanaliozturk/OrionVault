namespace Moongazing.OrionVault.GcpKms;

using System.Collections.Frozen;
using Grpc.Core;
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
/// <para>
/// The concrete provider is a fixed unwrap-once snapshot and deliberately does NOT implement
/// <see cref="IUnwrappedKeySource"/> (mirroring <c>AwsKmsKeyProvider</c> / <c>AzureKeyVaultKeyProvider</c>).
/// The refreshing envelope-key cache adapts a provider into an <see cref="IUnwrappedKeySource"/> via
/// the static <see cref="CreateUnwrappedKeySource"/> seam, whose unwrap actually re-runs the KMS
/// decrypt on every refresh.
/// </para>
/// </remarks>
public sealed class GcpKmsKeyProvider : IKeyProvider
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
    /// Decodes and decrypts every configured ciphertext entry against the validated
    /// <see cref="GcpKmsKeyProviderOptions.CryptoKeyName"/>. Shared by <see cref="CreateAsync"/>
    /// (unwrap-once) and the envelope-key cache refresh path so both go through identical
    /// validation and both decrypt under the exact configured crypto-key name. Static so it is
    /// callable before an instance exists.
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

        var cryptoKeyName = options.CryptoKeyName;
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

            // Pass the validated crypto-key name into the actual Decrypt request so the name the
            // provider validated is exactly the name KMS decrypts under.
            var plaintext = await decryptClient.DecryptAsync(cryptoKeyName, ciphertext, cancellationToken).ConfigureAwait(false);
            return (id, plaintext: (ReadOnlyMemory<byte>)plaintext);
        }).ToArray();

        var resolved = await Task.WhenAll(tasks).ConfigureAwait(false);
        return resolved.ToDictionary(x => x.id, x => x.plaintext);
    }

    /// <summary>
    /// Adapts a configured decrypt client + options into an <see cref="IUnwrappedKeySource"/> the
    /// core <see cref="Moongazing.OrionVault.Caching.CachingKeyProvider"/> refreshes against. Each
    /// refresh re-runs the KMS decrypt (it is NOT a cached snapshot), so a Cloud KMS key disabled /
    /// revoked / rotated mid-run is honoured. Used only on the opt-in caching path; the unwrap-once
    /// path never touches this.
    /// </summary>
    public static IUnwrappedKeySource CreateUnwrappedKeySource(
        IGcpKmsDecryptClient decryptClient,
        GcpKmsKeyProviderOptions options)
    {
        ArgumentNullException.ThrowIfNull(decryptClient);
        ArgumentNullException.ThrowIfNull(options);
        return new UnwrappedKeySource(decryptClient, options);
    }

    /// <summary>
    /// Maps a Cloud KMS gRPC status onto the cache's transient-vs-revocation policy. A revocation-
    /// class denial (key disabled / destroyed / not-found / permission withdrawn) must fail closed;
    /// everything else (unavailable, deadline, throttling, transient internal errors) is transient.
    /// </summary>
    internal static KeyUnwrapException? TryClassify(Exception ex)
    {
        if (ex is not RpcException rpc)
        {
            return null;
        }

        var kind = rpc.StatusCode switch
        {
            StatusCode.PermissionDenied => KeyUnwrapFailureKind.Revocation,
            StatusCode.Unauthenticated => KeyUnwrapFailureKind.Revocation,
            StatusCode.NotFound => KeyUnwrapFailureKind.Revocation,
            // A disabled / destroyed / pending-import crypto-key version decrypts with
            // FAILED_PRECONDITION; an invalid-for-this-key ciphertext with INVALID_ARGUMENT.
            StatusCode.FailedPrecondition => KeyUnwrapFailureKind.Revocation,
            StatusCode.InvalidArgument => KeyUnwrapFailureKind.Revocation,
            _ => KeyUnwrapFailureKind.Transient,
        };

        return new KeyUnwrapException(
            kind,
            $"GCP KMS decrypt failed with gRPC status {rpc.StatusCode}: {rpc.Status.Detail}",
            rpc);
    }

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

        public async Task<IReadOnlyDictionary<short, ReadOnlyMemory<byte>>> UnwrapAllAsync(
            CancellationToken cancellationToken)
        {
            try
            {
                return await GcpKmsKeyProvider
                    .UnwrapAllAsync(decryptClient, options, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (TryClassify(ex) is { } classified)
            {
                // Translate the cloud-SDK gRPC fault into the cache's transient / revocation
                // vocabulary so the provider-agnostic cache can fail closed on a revoked key.
                throw classified;
            }
        }
    }
}
