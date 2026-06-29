namespace Moongazing.OrionVault.GcpKms;

using Moongazing.OrionVault.Caching;

/// <summary>
/// Configuration for <see cref="GcpKmsKeyProvider"/>. The provider decrypts a configured map of
/// <c>(keyId, ciphertextBase64)</c> entries against a Google Cloud KMS crypto key at startup and
/// caches the resulting 32-byte plaintext data keys in process memory for the provider lifetime.
/// The KMS key material never leaves Google Cloud; OrionVault holds only the wrapped per-key data
/// keys.
/// </summary>
public sealed class GcpKmsKeyProviderOptions
{
    /// <summary>
    /// Fully-qualified Cloud KMS crypto-key resource name used to wrap the data keys, e.g.
    /// <c>projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}</c>. Decrypt
    /// resolves the primary key version automatically, so a bare crypto-key name (no
    /// <c>/cryptoKeyVersions/...</c> suffix) is the expected value here.
    /// </summary>
    public string CryptoKeyName { get; set; } = string.Empty;

    /// <summary>
    /// Key id used for all new encryptions. Must appear as a key in <see cref="WrappedKeys"/>.
    /// </summary>
    public short ActiveKeyId { get; set; }

    /// <summary>
    /// Map of key id to base64-encoded KMS ciphertext blob. The provider calls
    /// <c>KeyManagementServiceClient.Decrypt</c> on each entry once at startup. Old key ids stay
    /// resolvable so existing rows continue to decrypt during a rotation rollout.
    /// </summary>
    public IDictionary<short, string> WrappedKeys { get; } = new Dictionary<short, string>();

    /// <summary>
    /// Opt-in envelope-key caching (v0.4.0). Off by default: the provider unwraps once at startup
    /// and holds the plaintext for the provider lifetime. Enable with a TTL to re-fetch wrapped
    /// keys periodically so a Cloud KMS key disabled / rotated mid-run is picked up without a
    /// host restart.
    /// </summary>
    public EnvelopeKeyCacheOptions Cache { get; } = new();
}
