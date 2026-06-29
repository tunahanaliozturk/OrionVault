namespace Moongazing.OrionVault.Exceptions;

/// <summary>
/// How a failed data-key unwrap should be treated by the envelope-key cache when a previously
/// unwrapped snapshot is still in hand.
/// </summary>
public enum KeyUnwrapFailureKind
{
    /// <summary>
    /// A transient fault (network blip, KMS throttling / unavailable, deadline exceeded). The
    /// cache MAY keep serving the last-good snapshot through it when
    /// <see cref="Moongazing.OrionVault.Caching.EnvelopeKeyCacheOptions.ServeStaleOnRefreshFailure"/>
    /// is set. The next lookup retries the unwrap.
    /// </summary>
    Transient = 0,

    /// <summary>
    /// A revocation-class denial: the key was disabled, revoked, deleted / not-found, or access
    /// to it was withdrawn (permission denied / unauthenticated). The cache MUST fail closed and
    /// surface the error even when serve-stale is enabled: continuing to serve a key the KMS has
    /// explicitly stopped honouring defeats the point of envelope encryption (a revoked key must
    /// stop decrypting, not keep working until the TTL happens to lapse).
    /// </summary>
    Revocation = 1,
}

/// <summary>
/// Raised by an <see cref="Moongazing.OrionVault.Abstractions.IUnwrappedKeySource"/> when a data-key
/// unwrap against the backing KMS fails, carrying a <see cref="Kind"/> that tells the envelope-key
/// cache whether the failure is transient (serve-stale eligible) or a revocation-class denial
/// (fail closed). Providers translate their cloud-SDK exceptions into this so the provider-agnostic
/// <see cref="Moongazing.OrionVault.Caching.CachingKeyProvider"/> can apply the fail-open /
/// fail-closed policy without referencing any cloud SDK type.
/// </summary>
/// <remarks>
/// A failure surfaced as any other exception type is treated as <see cref="KeyUnwrapFailureKind.Transient"/>
/// by the cache, preserving the historical fail-open-on-error default for unclassified faults.
/// </remarks>
public sealed class KeyUnwrapException : Exception
{
    /// <summary>Constructs an unwrap failure of the given <paramref name="kind"/>.</summary>
    public KeyUnwrapException(KeyUnwrapFailureKind kind, string message, Exception? innerException = null)
        : base(message, innerException)
        => Kind = kind;

    public KeyUnwrapException()
    {
    }

    public KeyUnwrapException(string message)
        : base(message)
    {
    }

    public KeyUnwrapException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Whether the failure is transient (serve-stale eligible) or a revocation (fail closed).</summary>
    public KeyUnwrapFailureKind Kind { get; }
}
