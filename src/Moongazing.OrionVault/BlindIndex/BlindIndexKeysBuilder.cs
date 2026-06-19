namespace Moongazing.OrionVault.BlindIndex;

using Moongazing.OrionVault.Exceptions;

/// <summary>
/// Fluent builder for the versioned set of HMAC keys backing an
/// <see cref="Abstractions.IBlindIndexProvider"/>. Mirrors the encryption
/// <c>StaticKeysBuilder</c>: add one key per version, mark the active version for new writes,
/// and retain older versions so values indexed under them still match after a rotation.
/// <para>
/// Index keys are independent from encryption keys and must not be the same secret material:
/// the blind index trades a small amount of confidentiality (equal values are linkable) for
/// searchability, so leaking the index key must not weaken the encryption key.
/// </para>
/// </summary>
public sealed class BlindIndexKeysBuilder
{
    /// <summary>
    /// Minimum accepted HMAC key length, in bytes. Enforced on every key-registration path
    /// (this builder and direct <see cref="HmacBlindIndexProvider"/> construction) so a weak,
    /// low-entropy index key cannot be deployed regardless of how the provider is wired up.
    /// </summary>
    internal const int MinKeyBytes = 16;
    private readonly Dictionary<short, byte[]> _keys = new();

    /// <summary>
    /// Registers an index key <paramref name="version"/> from a base64-encoded secret. The
    /// decoded key must be at least 16 bytes; 32 bytes (matching the HMAC-SHA256 block-derived
    /// output) is recommended.
    /// </summary>
    /// <param name="version">The version identifier. Must be unique.</param>
    /// <param name="base64Key">The base64-encoded key material.</param>
    /// <exception cref="OrionVaultConfigurationException">
    /// Duplicate version, invalid base64, or a key shorter than 16 bytes.
    /// </exception>
    public BlindIndexKeysBuilder Add(short version, string base64Key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(base64Key);
        if (_keys.ContainsKey(version))
            throw new OrionVaultConfigurationException(
                $"Duplicate blind index key version {version} in BlindIndexKeysBuilder.");

        byte[] bytes;
        try { bytes = Convert.FromBase64String(base64Key); }
        catch (FormatException ex)
        {
            throw new OrionVaultConfigurationException(
                $"Blind index key version {version} is not valid base64.", ex);
        }

        return Add(version, bytes);
    }

    /// <summary>
    /// Registers an index key <paramref name="version"/> from raw bytes. The key must be at
    /// least 16 bytes. The array is copied defensively.
    /// </summary>
    /// <param name="version">The version identifier. Must be unique.</param>
    /// <param name="key">The raw key material (at least 16 bytes).</param>
    /// <exception cref="OrionVaultConfigurationException">
    /// Duplicate version or a key shorter than 16 bytes.
    /// </exception>
    public BlindIndexKeysBuilder Add(short version, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (_keys.ContainsKey(version))
            throw new OrionVaultConfigurationException(
                $"Duplicate blind index key version {version} in BlindIndexKeysBuilder.");
        if (key.Length < MinKeyBytes)
            throw new OrionVaultConfigurationException(
                $"Blind index key version {version} is {key.Length} bytes; expected at least {MinKeyBytes}.");

        _keys[version] = (byte[])key.Clone();
        return this;
    }

    internal IReadOnlyDictionary<short, byte[]> Build() => _keys;
}
