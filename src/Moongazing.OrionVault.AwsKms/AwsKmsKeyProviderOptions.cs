namespace Moongazing.OrionVault.AwsKms;

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
    /// Key id used for all new encryptions. Must appear as a key in <see cref="WrappedKeys"/>.
    /// </summary>
    public short ActiveKeyId { get; set; }

    /// <summary>
    /// Map of key id to base64-encoded KMS ciphertext blob. The provider calls
    /// <c>KeyManagementService.DecryptAsync</c> on each entry once at startup. Old key ids stay
    /// resolvable so existing rows continue to decrypt during a rotation rollout.
    /// </summary>
    public IDictionary<short, string> WrappedKeys { get; } = new Dictionary<short, string>();
}
