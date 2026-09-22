using System.Collections.Frozen;
using System.Net;
using Azure;
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
/// <para>
/// The concrete provider is a fixed unwrap-once snapshot and deliberately does NOT implement
/// <see cref="IUnwrappedKeySource"/> (mirroring the AWS / GCP / Vault providers). The refreshing
/// envelope-key cache adapts a provider into an <see cref="IUnwrappedKeySource"/> via the static
/// <see cref="CreateUnwrappedKeySource"/> seam, whose unwrap actually re-runs the vault unwrap on
/// every refresh.
/// </para>
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

    /// <inheritdoc />
    public int KeyCount => keys.Count;

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

        var unwrapped = await UnwrapAllAsync(unwrapClient, options, cancellationToken).ConfigureAwait(false);
        var map = unwrapped.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        return new AzureKeyVaultKeyProvider(options.ActiveKeyId, map);
    }

    /// <summary>
    /// Decodes and unwraps every configured ciphertext entry against the validated
    /// <see cref="AzureKeyVaultKeyProviderOptions.KeyName"/>. Shared by <see cref="CreateAsync"/>
    /// (unwrap-once) and the envelope-key cache refresh path so both go through identical
    /// validation. Static so it is callable before an instance exists.
    /// </summary>
    internal static async Task<IReadOnlyDictionary<short, ReadOnlyMemory<byte>>> UnwrapAllAsync(
        IKeyVaultUnwrapClient unwrapClient,
        AzureKeyVaultKeyProviderOptions options,
        CancellationToken cancellationToken)
    {
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
        return resolved.ToDictionary(x => x.id, x => x.plaintext);
    }

    /// <summary>
    /// Adapts a configured unwrap client + options into an <see cref="IUnwrappedKeySource"/> the
    /// core <see cref="Moongazing.OrionVault.Caching.CachingKeyProvider"/> refreshes against. Each
    /// refresh re-runs the vault unwrap (it is NOT a cached snapshot), so a KEK disabled / deleted
    /// or an access policy removed mid-run is honoured. Used only on the opt-in caching path; the
    /// unwrap-once path never touches this.
    /// </summary>
    public static IUnwrappedKeySource CreateUnwrappedKeySource(
        IKeyVaultUnwrapClient unwrapClient,
        AzureKeyVaultKeyProviderOptions options)
    {
        ArgumentNullException.ThrowIfNull(unwrapClient);
        ArgumentNullException.ThrowIfNull(options);
        return new UnwrappedKeySource(unwrapClient, options);
    }

    /// <summary>
    /// Maps an Azure Key Vault HTTP status onto the cache's transient-vs-revocation policy. A
    /// revocation-class denial (403 access policy / RBAC withdrawn, 404 key deleted or not found,
    /// 409 key disabled or soft-deleted) must fail closed; everything else (429 throttling, 5xx)
    /// is transient. A non-Azure exception is left unclassified (transient).
    /// </summary>
    internal static KeyUnwrapException? TryClassify(Exception ex)
    {
        if (ex is not RequestFailedException failed)
        {
            return null;
        }

        var kind = (HttpStatusCode)failed.Status switch
        {
            HttpStatusCode.Forbidden => KeyUnwrapFailureKind.Revocation,
            HttpStatusCode.NotFound => KeyUnwrapFailureKind.Revocation,
            HttpStatusCode.Conflict => KeyUnwrapFailureKind.Revocation,
            _ => KeyUnwrapFailureKind.Transient,
        };

        return new KeyUnwrapException(
            kind,
            $"Azure Key Vault unwrap failed with HTTP status {failed.Status} ({(HttpStatusCode)failed.Status}).",
            failed);
    }

    private sealed class UnwrappedKeySource : IUnwrappedKeySource
    {
        private readonly IKeyVaultUnwrapClient unwrapClient;
        private readonly AzureKeyVaultKeyProviderOptions options;

        public UnwrappedKeySource(IKeyVaultUnwrapClient unwrapClient, AzureKeyVaultKeyProviderOptions options)
        {
            this.unwrapClient = unwrapClient;
            this.options = options;
        }

        public short ActiveKeyId => options.ActiveKeyId;

        public async Task<IReadOnlyDictionary<short, ReadOnlyMemory<byte>>> UnwrapAllAsync(
            CancellationToken cancellationToken)
        {
            try
            {
                return await AzureKeyVaultKeyProvider
                    .UnwrapAllAsync(unwrapClient, options, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (TryClassify(ex) is { } classified)
            {
                // Translate the Azure SDK fault into the cache's transient / revocation
                // vocabulary so the provider-agnostic cache can fail closed on a revoked key.
                throw classified;
            }
        }
    }
}
