namespace Moongazing.OrionVault.Abstractions;

using Moongazing.OrionVault.BlindIndex;

/// <summary>
/// Computes deterministic, keyed <em>blind indexes</em> for values so callers can perform
/// equality search over encrypted data without decrypting it. A blind index is a keyed
/// one-way digest (HMAC) of a normalized value: equal plaintexts always produce equal
/// indexes, unequal plaintexts produce different indexes, and the index cannot be reversed
/// to the plaintext without the key.
/// <para>
/// This is distinct from <see cref="IEncryptor"/>. The encryptor produces a
/// <em>randomized</em>, non-deterministic ciphertext (two encryptions of the same value
/// differ), which is what you store as the protected value. The blind index produces a
/// <em>deterministic</em> token you store in a separate, searchable column and query with
/// an equality predicate. The two use independent keys.
/// </para>
/// <para>
/// Index keys are <em>versioned</em>. New writes use <see cref="ActiveVersion"/>; older
/// versions are retained so values indexed under a previous key still match after a key
/// rotation. The version is encoded in the produced index, so a stored index is
/// self-describing and a re-index sweep can detect rows still on an old version.
/// Implementations must be thread-safe and are registered as singletons.
/// </para>
/// </summary>
public interface IBlindIndexProvider
{
    /// <summary>
    /// The index key version used for all new index computations. Must be registered.
    /// </summary>
    short ActiveVersion { get; }

    /// <summary>
    /// Computes the blind index for <paramref name="value"/> under <see cref="ActiveVersion"/>.
    /// The returned <see cref="BlindIndexResult.Version"/> equals <see cref="ActiveVersion"/>.
    /// Use this when writing a new row.
    /// </summary>
    /// <param name="value">The plaintext to index. Normalized before hashing.</param>
    /// <exception cref="System.ArgumentNullException"><paramref name="value"/> is null.</exception>
    BlindIndexResult Compute(string value);

    /// <summary>
    /// Computes the blind index for <paramref name="value"/> under a specific
    /// <paramref name="version"/>. Use this to reproduce the index a row would have been
    /// written with under an older key, for example when verifying or re-indexing.
    /// </summary>
    /// <param name="value">The plaintext to index. Normalized before hashing.</param>
    /// <param name="version">The index key version to compute under. Must be registered.</param>
    /// <exception cref="System.ArgumentNullException"><paramref name="value"/> is null.</exception>
    /// <exception cref="Exceptions.OrionVaultKeyNotFoundException">
    /// <paramref name="version"/> is not registered.
    /// </exception>
    BlindIndexResult ComputeForVersion(string value, short version);

    /// <summary>
    /// Computes the blind index for <paramref name="value"/> under <em>every</em> registered
    /// version, newest first. Use this to build a search predicate that matches rows written
    /// under the current key as well as rows still carrying an index from a retained older
    /// key, so equality search keeps working across a key rotation before a re-index sweep
    /// completes. Each result's <see cref="BlindIndexResult.Version"/> identifies the version
    /// it was computed under.
    /// </summary>
    /// <param name="value">The plaintext to index. Normalized before hashing.</param>
    /// <exception cref="System.ArgumentNullException"><paramref name="value"/> is null.</exception>
    IReadOnlyList<BlindIndexResult> ComputeAllVersions(string value);

    /// <summary>
    /// Returns <c>true</c> if <paramref name="value"/> reproduces the supplied
    /// <paramref name="storedIndex"/>, resolving the key version from the index itself.
    /// Comparison is constant-time. Returns <c>false</c> (rather than throwing) when the
    /// stored index references an unknown version or is malformed, so a single rogue row
    /// cannot fault a search.
    /// </summary>
    /// <param name="value">The candidate plaintext.</param>
    /// <param name="storedIndex">A previously produced <see cref="BlindIndexResult.Bytes"/>.</param>
    /// <exception cref="System.ArgumentNullException">
    /// <paramref name="value"/> or <paramref name="storedIndex"/> is null.
    /// </exception>
    bool Matches(string value, byte[] storedIndex);
}
