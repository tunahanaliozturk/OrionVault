namespace Moongazing.OrionVault.BlindIndex;

using System.Buffers.Binary;

/// <summary>
/// The result of computing a blind index: a self-describing token whose on-disk layout is
/// <c>[version:2 BE | mac:32]</c> (34 bytes total). The leading version lets a stored index
/// be matched back to the key it was produced under, which is what makes search survive a
/// key rotation.
/// <para>
/// Store <see cref="Bytes"/> in your searchable column. Equal plaintexts indexed under the
/// same version produce byte-equal <see cref="Bytes"/>; that equality is exactly what an
/// <c>WHERE index = @probe</c> predicate relies on.
/// </para>
/// </summary>
public readonly struct BlindIndexResult : IEquatable<BlindIndexResult>
{
    /// <summary>Size in bytes of the version prefix.</summary>
    public const int VersionSize = 2;

    /// <summary>Size in bytes of the HMAC-SHA256 digest.</summary>
    public const int MacSize = 32;

    /// <summary>Total size in bytes of <see cref="Bytes"/>.</summary>
    public const int TotalSize = VersionSize + MacSize;

    private readonly byte[] _bytes;

    internal BlindIndexResult(short version, byte[] bytes)
    {
        Version = version;
        _bytes = bytes;
    }

    /// <summary>The index key version this token was computed under.</summary>
    public short Version { get; }

    /// <summary>
    /// The self-describing index token, layout <c>[version:2 BE | mac:32]</c>. This is the
    /// value to store and to compare with equality. Never null for a value produced by the
    /// provider.
    /// </summary>
    /// <remarks>
    /// CA1819: returning the backing array is intentional. The token is the public payload a
    /// caller persists verbatim and compares byte-for-byte; defensively cloning on every access
    /// would defeat the purpose and add allocations on the hot search path. The struct is
    /// effectively immutable (the array is never mutated after construction).
    /// </remarks>
#pragma warning disable CA1819 // Properties should not return arrays
    public byte[] Bytes => _bytes ?? [];
#pragma warning restore CA1819

    /// <summary>
    /// The 32-byte HMAC digest without the version prefix. Exposed for callers that store the
    /// version in a separate column.
    /// </summary>
    public ReadOnlySpan<byte> Mac => Bytes.AsSpan(VersionSize, MacSize);

    /// <summary>
    /// The index token as a lowercase hex string, convenient for a textual (e.g. char) column.
    /// </summary>
    /// <remarks>
    /// CA1308: lowercase hex is the deliberate, documented wire format for the textual column so
    /// stored indexes are stable and portable; this is presentation encoding, not a normalization
    /// that could be spoofed. Convert.ToHexString(...).ToLowerInvariant() is used (rather than the
    /// net9+ Convert.ToHexStringLower) to keep the multi-target build identical on net8.
    /// </remarks>
#pragma warning disable CA1308 // Normalize strings to uppercase
    public string ToHexString() => Convert.ToHexString(Bytes).ToLowerInvariant();
#pragma warning restore CA1308

    /// <summary>
    /// Reads the version prefix from a stored index token without recomputing it. Returns
    /// <c>false</c> if <paramref name="storedIndex"/> is too short to carry a version.
    /// </summary>
    public static bool TryReadVersion(ReadOnlySpan<byte> storedIndex, out short version)
    {
        if (storedIndex.Length < VersionSize)
        {
            version = 0;
            return false;
        }

        version = BinaryPrimitives.ReadInt16BigEndian(storedIndex[..VersionSize]);
        return true;
    }

    /// <inheritdoc />
    public bool Equals(BlindIndexResult other)
        => Version == other.Version && Bytes.AsSpan().SequenceEqual(other.Bytes);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is BlindIndexResult other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Version);
        hash.AddBytes(Bytes);
        return hash.ToHashCode();
    }

    /// <summary>Equality operator.</summary>
    public static bool operator ==(BlindIndexResult left, BlindIndexResult right) => left.Equals(right);

    /// <summary>Inequality operator.</summary>
    public static bool operator !=(BlindIndexResult left, BlindIndexResult right) => !left.Equals(right);
}
