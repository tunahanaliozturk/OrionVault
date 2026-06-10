using Azure.Security.KeyVault.Keys.Cryptography;

namespace Moongazing.OrionVault.AzureKeyVault;

/// <summary>
/// Configuration for <see cref="AzureKeyVaultKeyProvider"/>. The provider unwraps each
/// configured <c>(keyId, ciphertextBase64)</c> entry against an Azure Key Vault key encryption
/// key (KEK) at startup and caches the resulting 32-byte plaintext data keys in process
/// memory for the provider lifetime. The KEK itself never leaves the vault; OrionVault holds
/// only the wrapped per-key data keys.
/// </summary>
public sealed class AzureKeyVaultKeyProviderOptions
{
    /// <summary>
    /// Name of the Key Vault key used to wrap the data keys. May be a bare key name (the
    /// provider resolves it via the registered <c>KeyClient</c>) or a full key identifier URI.
    /// </summary>
    public string KeyName { get; set; } = string.Empty;

    /// <summary>
    /// Optional KEK version. Leave null (default) to use the current version; set to pin the
    /// provider to a specific historical KEK version.
    /// </summary>
    public string? KeyVersion { get; set; }

    /// <summary>
    /// Wrap algorithm used during unwrap. Default <see cref="KeyWrapAlgorithm.RsaOaep256"/>
    /// for RSA KEKs. Use <see cref="KeyWrapAlgorithm.A256KW"/> for HSM-backed AES keys.
    /// </summary>
    public KeyWrapAlgorithm WrapAlgorithm { get; set; } = KeyWrapAlgorithm.RsaOaep256;

    /// <summary>
    /// Key id used for all new encryptions. Must appear as a key in <see cref="WrappedKeys"/>.
    /// </summary>
    public short ActiveKeyId { get; set; }

    /// <summary>
    /// Map of key id to base64-encoded wrapped data key. The provider calls Azure Key Vault
    /// once per entry at startup. Old key ids stay resolvable so existing rows continue to
    /// decrypt during a rotation rollout.
    /// </summary>
    public IDictionary<short, string> WrappedKeys { get; } = new Dictionary<short, string>();
}
