namespace Moongazing.OrionVault.Abstractions;

/// <summary>
/// The asynchronous "unwrap every configured data key" operation behind an envelope-encryption
/// key provider (AWS KMS, Azure Key Vault, GCP KMS, HashiCorp Vault, ...). It is the single
/// expensive, network-bound step those providers run at startup: decrypt / unwrap each
/// configured ciphertext blob against the remote KMS and return the resulting plaintext map.
/// </summary>
/// <remarks>
/// Factored out so the core <see cref="Moongazing.OrionVault.Caching.CachingKeyProvider"/> can
/// drive a refreshing cache over any provider uniformly, without the core taking a dependency on
/// any cloud SDK. A provider implements this (the AWS / Azure / GCP / Vault adapters do) and the
/// cache calls <see cref="UnwrapAllAsync"/> once per refresh window. The default
/// (unwrap-once-at-startup) path does not use this seam at all, so existing wiring is unchanged.
/// </remarks>
public interface IUnwrappedKeySource
{
    /// <summary>
    /// The key id used for all new encryptions. Surfaced so the cache can expose
    /// <see cref="IKeyProvider.ActiveKeyId"/> without unwrapping anything.
    /// </summary>
    short ActiveKeyId { get; }

    /// <summary>
    /// Unwraps every configured data key against the backing KMS and returns a fresh map of
    /// key id to 32-byte plaintext. Implementations MUST return a newly materialised map on
    /// each call (the cache stores the result and replaces it wholesale on refresh) and MUST
    /// propagate transport / authorization failures so the cache can decide whether to keep
    /// serving the previous snapshot or fail.
    /// </summary>
    Task<IReadOnlyDictionary<short, ReadOnlyMemory<byte>>> UnwrapAllAsync(CancellationToken cancellationToken);
}
