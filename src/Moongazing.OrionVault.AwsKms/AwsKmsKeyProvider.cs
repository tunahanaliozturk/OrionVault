namespace Moongazing.OrionVault.AwsKms;

using System.Collections.Frozen;
using System.Net;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
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
/// <para>
/// The concrete provider is a fixed unwrap-once snapshot and deliberately does NOT implement
/// <see cref="IUnwrappedKeySource"/> (mirroring the Azure / GCP / Vault providers). The
/// refreshing envelope-key cache adapts a provider into an <see cref="IUnwrappedKeySource"/> via
/// the static <see cref="CreateUnwrappedKeySource"/> seam, whose unwrap actually re-runs the KMS
/// decrypt on every refresh.
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

    /// <inheritdoc />
    public int KeyCount => keys.Count;

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
        // Snapshot before starting concurrent KMS calls: a mutable options dictionary must not
        // cause different wrapped keys in one provider build to receive different contexts.
        var context = new Dictionary<string, string>(options.EncryptionContext, StringComparer.Ordinal);
        if (context.Any(static entry => string.IsNullOrWhiteSpace(entry.Key) || string.IsNullOrWhiteSpace(entry.Value)))
        {
            throw new OrionVaultConfigurationException(
                "AwsKmsKeyProviderOptions.EncryptionContext requires non-empty names and values.");
        }

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
            var request = new DecryptRequest { CiphertextBlob = stream, KeyId = cmk };
            if (context.Count != 0)
            {
                request.EncryptionContext = context;
            }

            var response = await kms.DecryptAsync(request, cancellationToken).ConfigureAwait(false);
            return (id, plaintext: (ReadOnlyMemory<byte>)response.Plaintext.ToArray());
        }).ToArray();

        var resolved = await Task.WhenAll(tasks).ConfigureAwait(false);
        return resolved.ToDictionary(x => x.id, x => x.plaintext);
    }

    /// <summary>
    /// Adapts a configured KMS client + options into an <see cref="IUnwrappedKeySource"/> the
    /// core <see cref="Moongazing.OrionVault.Caching.CachingKeyProvider"/> refreshes against. Each
    /// refresh re-runs the KMS decrypt (it is NOT a cached snapshot), so a CMK disabled /
    /// scheduled for deletion / access-withdrawn mid-run is honoured. Used only on the opt-in
    /// caching path; the unwrap-once path never touches this.
    /// </summary>
    public static IUnwrappedKeySource CreateUnwrappedKeySource(
        IAmazonKeyManagementService kms,
        AwsKmsKeyProviderOptions options)
    {
        ArgumentNullException.ThrowIfNull(kms);
        ArgumentNullException.ThrowIfNull(options);
        return new UnwrappedKeySource(kms, options);
    }

    /// <summary>
    /// Maps an AWS KMS SDK fault onto the cache's transient-vs-revocation policy. A revocation-
    /// class denial (CMK disabled / pending deletion / not found, access withdrawn, or a blob the
    /// pinned CMK will not decrypt) must fail closed; everything else (throttling, KMS internal
    /// errors, dependency timeouts, 5xx) is transient. A non-AWS exception is left unclassified.
    /// </summary>
    internal static KeyUnwrapException? TryClassify(Exception ex)
    {
        if (ex is not AmazonServiceException aws)
        {
            return null;
        }

        var kind = aws switch
        {
            // Disabled, pending deletion, pending import: the CMK exists but must not be used.
            KMSInvalidStateException => KeyUnwrapFailureKind.Revocation,
            DisabledException => KeyUnwrapFailureKind.Revocation,
            NotFoundException => KeyUnwrapFailureKind.Revocation,
            // The blob is not decryptable under the pinned CMK - the shape a substituted or
            // re-pointed ciphertext takes, and the one a rotated-away key takes.
            InvalidCiphertextException => KeyUnwrapFailureKind.Revocation,
            IncorrectKeyException => KeyUnwrapFailureKind.Revocation,
            // Throttling and KMS-side faults are retryable, not a decision about the key.
            LimitExceededException => KeyUnwrapFailureKind.Transient,
            KMSInternalException => KeyUnwrapFailureKind.Transient,
            DependencyTimeoutException => KeyUnwrapFailureKind.Transient,
            // AccessDenied has no generated model type; it arrives as a plain service exception
            // carrying the error code / 403. Withdrawn kms:Decrypt is a revocation.
            _ when aws.StatusCode == HttpStatusCode.Forbidden
                || string.Equals(aws.ErrorCode, "AccessDeniedException", StringComparison.Ordinal)
                => KeyUnwrapFailureKind.Revocation,
            _ => KeyUnwrapFailureKind.Transient,
        };

        return new KeyUnwrapException(
            kind,
            $"AWS KMS decrypt failed with error code '{aws.ErrorCode}' (HTTP {(int)aws.StatusCode}): {aws.Message}",
            aws);
    }

    private sealed class UnwrappedKeySource : IUnwrappedKeySource
    {
        private readonly IAmazonKeyManagementService kms;
        private readonly AwsKmsKeyProviderOptions options;

        public UnwrappedKeySource(IAmazonKeyManagementService kms, AwsKmsKeyProviderOptions options)
        {
            this.kms = kms;
            this.options = options;
        }

        public short ActiveKeyId => options.ActiveKeyId;

        public async Task<IReadOnlyDictionary<short, ReadOnlyMemory<byte>>> UnwrapAllAsync(
            CancellationToken cancellationToken)
        {
            try
            {
                return await AwsKmsKeyProvider
                    .UnwrapAllAsync(kms, options, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (TryClassify(ex) is { } classified)
            {
                // Translate the cloud-SDK fault into the cache's transient / revocation
                // vocabulary so the provider-agnostic cache can fail closed on a revoked key.
                throw classified;
            }
        }
    }
}
