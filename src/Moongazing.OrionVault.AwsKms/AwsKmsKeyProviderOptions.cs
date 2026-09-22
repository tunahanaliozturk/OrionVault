namespace Moongazing.OrionVault.AwsKms;

using Moongazing.OrionVault.Caching;

/// <summary>
/// Configuration for <see cref="AwsKmsKeyProvider"/>. The provider decrypts a configured map
/// of <c>(keyId, ciphertextBase64)</c> entries against the supplied AWS KMS client at startup
/// and caches the resulting 32-byte plaintext keys in process memory for the lifetime of the
/// provider. The KMS customer master key (CMK) never leaves AWS; OrionVault holds only the
/// per-key data keys it wraps.
/// </summary>
public sealed class AwsKmsKeyProviderOptions
{
    /// <summary>
    /// The customer master key (CMK) every configured blob must be wrapped under: a key id,
    /// key ARN, alias name (<c>alias/orionvault</c>) or alias ARN. REQUIRED.
    /// <para>
    /// This value is passed as <c>DecryptRequest.KeyId</c> so KMS decrypts under the CMK the
    /// deployment declares instead of resolving one from the ciphertext blob's own metadata.
    /// Without it, anyone who can influence <see cref="WrappedKeys"/> - a config store, an
    /// environment variable, an <c>appsettings.json</c> baked into a container image, a
    /// compromised deploy pipeline - can substitute a blob they wrapped under a CMK in their
    /// own account that the host principal happens to hold <c>kms:Decrypt</c> on (reachable via
    /// cross-account key policies or a <c>Resource: "*"</c> grant). KMS would resolve that key
    /// from the blob and decrypt it happily, making the attacker's data key the active key. Byte
    /// length is the only other thing the provider can check, and a 32-byte attacker key passes
    /// it. Pinning the CMK is AWS's documented practice for symmetric decrypt for exactly this
    /// reason.
    /// </para>
    /// </summary>
    public string KeyId { get; set; } = string.Empty;

    /// <summary>
    /// Key id used for all new encryptions. Must appear as a key in <see cref="WrappedKeys"/>.
    /// </summary>
    public short ActiveKeyId { get; set; }

    /// <summary>
    /// Map of key id to base64-encoded KMS ciphertext blob. The provider calls
    /// <c>KeyManagementService.DecryptAsync</c> on each entry once at startup. Old key ids stay
    /// resolvable so existing rows continue to decrypt during a rotation rollout.
    /// </summary>
    public IDictionary<short, string> WrappedKeys { get; } = new Dictionary<short, string>();

    /// <summary>
    /// Opt-in envelope-key caching. Off by default: the provider unwraps once at startup and
    /// holds the plaintext for the provider lifetime. Enable with a TTL to re-fetch the wrapped
    /// keys periodically so a CMK disabled / scheduled for deletion / access-withdrawn mid-run
    /// is picked up without a host restart.
    /// </summary>
    public EnvelopeKeyCacheOptions Cache { get; } = new();
}
