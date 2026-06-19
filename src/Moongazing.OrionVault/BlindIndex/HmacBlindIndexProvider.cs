namespace Moongazing.OrionVault.BlindIndex;

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Exceptions;

/// <summary>
/// HMAC-SHA256 implementation of <see cref="IBlindIndexProvider"/>. Computes a deterministic,
/// keyed digest of a normalized value. Uses only the cross-framework
/// <see cref="HMACSHA256.HashData(System.ReadOnlySpan{byte}, System.ReadOnlySpan{byte})"/> API
/// so output is byte-identical on net8, net9, and net10 and stable across processes and hosts
/// configured with the same key. Thread-safe; register as a singleton.
/// </summary>
public sealed class HmacBlindIndexProvider : IBlindIndexProvider
{
    private readonly Dictionary<short, byte[]> _keys;
    private readonly short[] _versionsNewestFirst;
    private readonly BlindIndexNormalization _normalization;

    /// <summary>
    /// Creates a provider over the supplied versioned keys.
    /// </summary>
    /// <param name="keys">Version to key-material map. Must be non-empty.</param>
    /// <param name="activeVersion">The version used for new index computations. Must be a key in <paramref name="keys"/>.</param>
    /// <param name="normalization">How values are normalized before hashing.</param>
    /// <exception cref="System.ArgumentNullException"><paramref name="keys"/> is null.</exception>
    /// <exception cref="OrionVaultConfigurationException">
    /// <paramref name="keys"/> is empty or <paramref name="activeVersion"/> is not registered.
    /// </exception>
    public HmacBlindIndexProvider(
        IReadOnlyDictionary<short, byte[]> keys,
        short activeVersion,
        BlindIndexNormalization normalization = BlindIndexNormalization.TrimAndLowercaseInvariant)
    {
        ArgumentNullException.ThrowIfNull(keys);
        if (keys.Count == 0)
            throw new OrionVaultConfigurationException(
                "HmacBlindIndexProvider requires at least one key version.");
        if (!keys.ContainsKey(activeVersion))
            throw new OrionVaultConfigurationException(
                $"Blind index ActiveVersion {activeVersion} is not registered. Registered versions: [{string.Join(", ", keys.Keys)}].");

        // Copy defensively so a caller mutating the source dictionary or arrays cannot change
        // index output after construction (which would silently break search).
        var copy = new Dictionary<short, byte[]>(keys.Count);
        foreach (var (version, key) in keys)
        {
            copy[version] = (byte[])key.Clone();
        }

        _keys = copy;
        ActiveVersion = activeVersion;
        _normalization = normalization;
        // Newest version first so ComputeAllVersions yields the most-likely match first, which
        // lets a caller short-circuit a search predicate on the common (current-key) case.
        _versionsNewestFirst = copy.Keys.OrderByDescending(v => v).ToArray();
    }

    /// <inheritdoc />
    public short ActiveVersion { get; }

    /// <inheritdoc />
    public BlindIndexResult Compute(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return ComputeCore(value, ActiveVersion);
    }

    /// <inheritdoc />
    public BlindIndexResult ComputeForVersion(string value, short version)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!_keys.ContainsKey(version))
            throw new OrionVaultKeyNotFoundException(version);
        return ComputeCore(value, version);
    }

    /// <inheritdoc />
    public IReadOnlyList<BlindIndexResult> ComputeAllVersions(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        // Normalize once; only the key changes per version.
        var normalized = Encoding.UTF8.GetBytes(Normalize(value));
        var results = new BlindIndexResult[_versionsNewestFirst.Length];
        for (var i = 0; i < _versionsNewestFirst.Length; i++)
        {
            var version = _versionsNewestFirst[i];
            results[i] = Pack(version, _keys[version], normalized);
        }

        return results;
    }

    /// <inheritdoc />
    public bool Matches(string value, byte[] storedIndex)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(storedIndex);

        // A malformed or unknown-version stored index is a non-match, never an exception: one
        // bad row must not fault an entire search sweep.
        if (storedIndex.Length != BlindIndexResult.TotalSize)
            return false;
        if (!BlindIndexResult.TryReadVersion(storedIndex, out var version))
            return false;
        if (!_keys.TryGetValue(version, out var key))
            return false;

        var normalized = Encoding.UTF8.GetBytes(Normalize(value));
        Span<byte> expectedMac = stackalloc byte[BlindIndexResult.MacSize];
        HMACSHA256.HashData(key, normalized, expectedMac);

        // Constant-time comparison so a timing side channel cannot reveal how many leading
        // bytes of the digest matched.
        return CryptographicOperations.FixedTimeEquals(
            expectedMac, storedIndex.AsSpan(BlindIndexResult.VersionSize, BlindIndexResult.MacSize));
    }

    private BlindIndexResult ComputeCore(string value, short version)
    {
        var normalized = Encoding.UTF8.GetBytes(Normalize(value));
        return Pack(version, _keys[version], normalized);
    }

    private static BlindIndexResult Pack(short version, byte[] key, byte[] normalized)
    {
        var bytes = new byte[BlindIndexResult.TotalSize];
        BinaryPrimitives.WriteInt16BigEndian(bytes.AsSpan(0, BlindIndexResult.VersionSize), version);
        HMACSHA256.HashData(key, normalized, bytes.AsSpan(BlindIndexResult.VersionSize, BlindIndexResult.MacSize));
        return new BlindIndexResult(version, bytes);
    }

    // CA1308: lowercasing is the intended semantic here (case-insensitive equality for emails /
    // usernames), not a security-sensitive normalization. ToUpperInvariant would change which
    // values collide and is not what callers asked for. Invariant culture keeps indexes portable.
#pragma warning disable CA1308 // Normalize strings to uppercase
    private string Normalize(string value) => _normalization switch
    {
        BlindIndexNormalization.TrimAndLowercaseInvariant => value.Trim().ToLowerInvariant(),
        BlindIndexNormalization.Trim => value.Trim(),
        BlindIndexNormalization.None => value,
        _ => value,
    };
#pragma warning restore CA1308
}
