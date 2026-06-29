namespace Moongazing.OrionVault.HashiCorpVault;

using System.Collections.Frozen;
using System.Net;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Exceptions;
using VaultSharp.Core;

/// <summary>
/// HashiCorp Vault transit-engine-backed <see cref="IKeyProvider"/>. Holds a map of OrionVault key
/// ids to the 32-byte plaintext data keys obtained by decrypting the configured transit ciphertext
/// strings at startup. The transit key never leaves Vault; ciphertext strings stored in OrionVault
/// config / source control are useless without Vault access.
/// </summary>
/// <remarks>
/// Multi-key read, single-key write rotation (same shape as <c>AwsKmsKeyProvider</c>): the active
/// id (<see cref="ActiveKeyId"/>) is used for new encryptions; previously-active ids remain in the
/// map until rows encrypted under them are re-encrypted by the v0.2.0 background re-encryption
/// service. Each entry's plaintext is held in memory once and reused; consumers MUST register the
/// provider as singleton (the default <c>AddOrionVaultHashiCorpVault</c> extension enforces this).
/// <para>
/// The concrete provider is a fixed unwrap-once snapshot and deliberately does NOT implement
/// <see cref="IUnwrappedKeySource"/> (mirroring <c>AwsKmsKeyProvider</c> / <c>AzureKeyVaultKeyProvider</c>
/// / <c>GcpKmsKeyProvider</c>). The refreshing envelope-key cache adapts a provider into an
/// <see cref="IUnwrappedKeySource"/> via the static <see cref="CreateUnwrappedKeySource"/> seam,
/// whose unwrap actually re-runs the Vault transit decrypt on every refresh.
/// </para>
/// </remarks>
public sealed class HashiCorpVaultKeyProvider : IKeyProvider
{
    private readonly FrozenDictionary<short, ReadOnlyMemory<byte>> keys;

    /// <inheritdoc />
    public short ActiveKeyId { get; }

    /// <summary>
    /// Constructs the provider from a pre-built dictionary. Use the <see cref="CreateAsync"/>
    /// factory in production to decrypt the configured transit ciphertext strings against Vault;
    /// this constructor exists for tests and for advanced consumers that already hold the plaintext
    /// keys.
    /// </summary>
    public HashiCorpVaultKeyProvider(short activeKeyId, IDictionary<short, ReadOnlyMemory<byte>> plaintextKeys)
    {
        ArgumentNullException.ThrowIfNull(plaintextKeys);
        if (!plaintextKeys.ContainsKey(activeKeyId))
        {
            throw new OrionVaultConfigurationException(
                $"HashiCorpVaultKeyProvider: active key id {activeKeyId} is not in the supplied plaintext-key map. " +
                $"Registered ids: [{string.Join(", ", plaintextKeys.Keys)}].");
        }
        foreach (var (id, key) in plaintextKeys)
        {
            if (key.Length != 32)
            {
                throw new OrionVaultConfigurationException(
                    $"HashiCorpVaultKeyProvider: key id {id} length is {key.Length} bytes; OrionVault requires exactly 32.");
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
    /// Decrypts each configured transit ciphertext string via the supplied
    /// <see cref="IVaultTransitDecryptClient"/> and returns a ready-to-use provider. Call once at
    /// host startup. The Vault calls run concurrently to keep startup fast.
    /// </summary>
    public static async Task<HashiCorpVaultKeyProvider> CreateAsync(
        IVaultTransitDecryptClient decryptClient,
        HashiCorpVaultKeyProviderOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(decryptClient);
        ArgumentNullException.ThrowIfNull(options);

        var unwrapped = await UnwrapAllAsync(decryptClient, options, cancellationToken).ConfigureAwait(false);
        var map = unwrapped.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        return new HashiCorpVaultKeyProvider(options.ActiveKeyId, map);
    }

    /// <summary>
    /// Decrypts every configured transit ciphertext entry against the validated
    /// <see cref="HashiCorpVaultKeyProviderOptions.TransitKeyName"/>. Shared by
    /// <see cref="CreateAsync"/> (unwrap-once) and the envelope-key cache refresh path so both go
    /// through identical validation. Static so it is callable before an instance exists.
    /// </summary>
    internal static async Task<IReadOnlyDictionary<short, ReadOnlyMemory<byte>>> UnwrapAllAsync(
        IVaultTransitDecryptClient decryptClient,
        HashiCorpVaultKeyProviderOptions options,
        CancellationToken cancellationToken)
    {
        if (options.WrappedKeys.Count == 0)
        {
            throw new OrionVaultConfigurationException(
                "HashiCorpVaultKeyProviderOptions.WrappedKeys is empty. At least one (keyId, transitCiphertext) entry is required.");
        }
        if (string.IsNullOrWhiteSpace(options.TransitKeyName))
        {
            throw new OrionVaultConfigurationException(
                "HashiCorpVaultKeyProviderOptions.TransitKeyName must be a non-empty Vault transit key name.");
        }

        var tasks = options.WrappedKeys.Select(async pair =>
        {
            var (id, ciphertext) = pair;
            if (string.IsNullOrWhiteSpace(ciphertext))
            {
                throw new OrionVaultConfigurationException(
                    $"HashiCorpVaultKeyProvider: key id {id} ciphertext is null or whitespace.");
            }

            byte[] plaintext;
            try
            {
                plaintext = await decryptClient.DecryptAsync(ciphertext, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (TryClassify(ex) is { } classified)
            {
                // Translate the Vault transport fault into the cache's transient / revocation
                // vocabulary, scoped to the failing key id, so the provider-agnostic cache can fail
                // closed on a revoked / disabled transit key while still serving stale through a
                // momentary Vault blip.
                throw new KeyUnwrapException(
                    classified.Kind,
                    $"HashiCorpVaultKeyProvider: key id {id} transit decrypt failed. {classified.Message}",
                    ex);
            }

            if (plaintext is null || plaintext.Length == 0)
            {
                throw new OrionVaultConfigurationException(
                    $"HashiCorpVaultKeyProvider: key id {id} decrypted to zero bytes.");
            }
            return (id, plaintext: (ReadOnlyMemory<byte>)plaintext);
        }).ToArray();

        var resolved = await Task.WhenAll(tasks).ConfigureAwait(false);
        return resolved.ToDictionary(x => x.id, x => x.plaintext);
    }

    /// <summary>
    /// Adapts a configured decrypt client + options into an <see cref="IUnwrappedKeySource"/> the
    /// core <see cref="Moongazing.OrionVault.Caching.CachingKeyProvider"/> refreshes against. Each
    /// refresh re-runs the Vault transit decrypt (it is NOT a cached snapshot), so a transit key
    /// disabled / rotated / access-withdrawn mid-run is honoured. Used only on the opt-in caching
    /// path; the unwrap-once path never touches this.
    /// </summary>
    public static IUnwrappedKeySource CreateUnwrappedKeySource(
        IVaultTransitDecryptClient decryptClient,
        HashiCorpVaultKeyProviderOptions options)
    {
        ArgumentNullException.ThrowIfNull(decryptClient);
        ArgumentNullException.ThrowIfNull(options);
        return new UnwrappedKeySource(decryptClient, options);
    }

    /// <summary>
    /// Maps a Vault API HTTP status onto the cache's transient-vs-revocation policy. A revocation-
    /// class denial (transit key disabled / deleted, ciphertext no longer decryptable, or access
    /// withdrawn: 400 / 401 / 403 / 404) must fail closed; everything else (5xx, 429 throttling,
    /// 412 sealed / standby) is transient. A non-Vault exception is left unclassified (transient).
    /// </summary>
    internal static KeyUnwrapException? TryClassify(Exception ex)
    {
        if (ex is not VaultApiException vault)
        {
            return null;
        }

        var status = vault.HttpStatusCode;
        var kind = status switch
        {
            HttpStatusCode.BadRequest => KeyUnwrapFailureKind.Revocation,
            HttpStatusCode.Unauthorized => KeyUnwrapFailureKind.Revocation,
            HttpStatusCode.Forbidden => KeyUnwrapFailureKind.Revocation,
            HttpStatusCode.NotFound => KeyUnwrapFailureKind.Revocation,
            _ => KeyUnwrapFailureKind.Transient,
        };

        return new KeyUnwrapException(
            kind,
            $"Vault transit decrypt failed with HTTP status {(int)status} ({status}).",
            vault);
    }

    private sealed class UnwrappedKeySource : IUnwrappedKeySource
    {
        private readonly IVaultTransitDecryptClient decryptClient;
        private readonly HashiCorpVaultKeyProviderOptions options;

        public UnwrappedKeySource(IVaultTransitDecryptClient decryptClient, HashiCorpVaultKeyProviderOptions options)
        {
            this.decryptClient = decryptClient;
            this.options = options;
        }

        public short ActiveKeyId => options.ActiveKeyId;

        public Task<IReadOnlyDictionary<short, ReadOnlyMemory<byte>>> UnwrapAllAsync(
            CancellationToken cancellationToken)
            => HashiCorpVaultKeyProvider.UnwrapAllAsync(decryptClient, options, cancellationToken);
    }
}
