namespace Moongazing.OrionVault.BlindIndex;

using System.Buffers;
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
    // Encode the normalized UTF-8 input into a stack buffer when it fits, falling back to a
    // pooled (cleared on return) buffer for longer values so a large input cannot overflow the
    // stack. 256 bytes covers the email/username inputs blind indexes are built for without
    // touching the heap; the threshold is a transient-buffer size, not part of the wire format,
    // so it can change without affecting any computed index.
    private const int MaxStackInputBytes = 256;

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
    /// <paramref name="keys"/> is empty, <paramref name="activeVersion"/> is not registered,
    /// or any supplied key is null or shorter than <see cref="BlindIndexKeysBuilder.MinKeyBytes"/> bytes.
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
        // index output after construction (which would silently break search). Validate every
        // version (active and retained) against the same minimum length BlindIndexKeysBuilder.Add
        // enforces, so a direct (non-DI) caller cannot silently deploy a low-entropy index key
        // that the configured path would have rejected.
        var copy = new Dictionary<short, byte[]>(keys.Count);
        foreach (var (version, key) in keys)
        {
            if (key is null)
                throw new OrionVaultConfigurationException(
                    $"Blind index key version {version} is null.");
            if (key.Length < BlindIndexKeysBuilder.MinKeyBytes)
                throw new OrionVaultConfigurationException(
                    $"Blind index key version {version} is {key.Length} bytes; expected at least {BlindIndexKeysBuilder.MinKeyBytes}.");

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
        var results = new BlindIndexResult[_versionsNewestFirst.Length];

        // Encode the normalized input once; only the key changes per version.
        var normalized = Normalize(value);
        var maxBytes = Encoding.UTF8.GetMaxByteCount(normalized.Length);
        byte[]? rented = null;
        Span<byte> buffer = maxBytes <= MaxStackInputBytes
            ? stackalloc byte[MaxStackInputBytes]
            : (rented = ArrayPool<byte>.Shared.Rent(maxBytes));
        try
        {
            var written = Encoding.UTF8.GetBytes(normalized, buffer);
            var input = buffer[..written];
            for (var i = 0; i < _versionsNewestFirst.Length; i++)
            {
                var version = _versionsNewestFirst[i];
                results[i] = Pack(version, _keys[version], input);
            }
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented, clearArray: true);
            }
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

        Span<byte> expectedMac = stackalloc byte[BlindIndexResult.MacSize];

        var normalized = Normalize(value);
        var maxBytes = Encoding.UTF8.GetMaxByteCount(normalized.Length);
        byte[]? rented = null;
        Span<byte> buffer = maxBytes <= MaxStackInputBytes
            ? stackalloc byte[MaxStackInputBytes]
            : (rented = ArrayPool<byte>.Shared.Rent(maxBytes));
        try
        {
            var written = Encoding.UTF8.GetBytes(normalized, buffer);
            HMACSHA256.HashData(key, buffer[..written], expectedMac);
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented, clearArray: true);
            }
        }

        // Constant-time comparison so a timing side channel cannot reveal how many leading
        // bytes of the digest matched.
        return CryptographicOperations.FixedTimeEquals(
            expectedMac, storedIndex.AsSpan(BlindIndexResult.VersionSize, BlindIndexResult.MacSize));
    }

    private BlindIndexResult ComputeCore(string value, short version)
    {
        var key = _keys[version];

        var normalized = Normalize(value);
        var maxBytes = Encoding.UTF8.GetMaxByteCount(normalized.Length);
        byte[]? rented = null;
        Span<byte> buffer = maxBytes <= MaxStackInputBytes
            ? stackalloc byte[MaxStackInputBytes]
            : (rented = ArrayPool<byte>.Shared.Rent(maxBytes));
        try
        {
            var written = Encoding.UTF8.GetBytes(normalized, buffer);
            return Pack(version, key, buffer[..written]);
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented, clearArray: true);
            }
        }
    }

    private static BlindIndexResult Pack(short version, ReadOnlySpan<byte> key, ReadOnlySpan<byte> normalized)
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
