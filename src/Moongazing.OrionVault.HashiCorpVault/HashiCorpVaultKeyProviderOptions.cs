namespace Moongazing.OrionVault.HashiCorpVault;

using Moongazing.OrionVault.Caching;

/// <summary>
/// Configuration for <see cref="HashiCorpVaultKeyProvider"/>. The provider decrypts a configured
/// map of <c>(keyId, transitCiphertext)</c> entries against a HashiCorp Vault transit key at
/// startup and caches the resulting 32-byte plaintext data keys in process memory for the provider
/// lifetime. The transit key never leaves Vault; OrionVault holds only the wrapped per-key data
/// keys.
/// </summary>
public sealed class HashiCorpVaultKeyProviderOptions
{
    /// <summary>
    /// Name of the Vault transit key used to wrap the data keys (the key passed to the transit
    /// <c>decrypt</c> endpoint).
    /// </summary>
    public string TransitKeyName { get; set; } = string.Empty;

    /// <summary>
    /// Mount point of the transit secrets engine. Defaults to <c>transit</c> (Vault's default mount
    /// path for that engine). Set this if the engine was mounted elsewhere.
    /// </summary>
    public string MountPoint { get; set; } = "transit";

    /// <summary>
    /// Key id used for all new encryptions. Must appear as a key in <see cref="WrappedKeys"/>.
    /// </summary>
    public short ActiveKeyId { get; set; }

    /// <summary>
    /// Map of key id to Vault transit ciphertext (the <c>vault:v1:...</c> string returned by the
    /// transit <c>encrypt</c> endpoint when the data key was wrapped). The provider calls the
    /// transit <c>decrypt</c> endpoint on each entry once at startup. Old key ids stay resolvable
    /// so existing rows continue to decrypt during a rotation rollout.
    /// </summary>
    public IDictionary<short, string> WrappedKeys { get; } = new Dictionary<short, string>();

    /// <summary>
    /// Opt-in envelope-key caching (v0.4.0). Off by default: the provider unwraps once at startup
    /// and holds the plaintext for the provider lifetime. Enable with a TTL to re-fetch wrapped
    /// keys periodically so a transit key rotated / disabled mid-run is picked up without a host
    /// restart.
    /// </summary>
    public EnvelopeKeyCacheOptions Cache { get; } = new();
}
