namespace Moongazing.OrionVault.GcpKms;

/// <summary>
/// Narrow abstraction over the Google Cloud KMS decrypt call. Exists so the provider can be
/// unit-tested without a real <c>KeyManagementServiceClient</c> / network; the production
/// implementation forwards to <c>KeyManagementServiceClient.DecryptAsync</c> against the
/// configured crypto-key resource name.
/// </summary>
public interface IGcpKmsDecryptClient
{
    /// <summary>
    /// Decrypt a single wrapped data key. Implementations should propagate transport / KMS
    /// errors to the caller; OrionVault surfaces them as
    /// <see cref="Moongazing.OrionVault.Exceptions.OrionVaultConfigurationException"/> at startup
    /// so a misconfigured deployment fails fast.
    /// </summary>
    /// <param name="ciphertext">The KMS ciphertext blob.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The plaintext data key.</returns>
    Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken cancellationToken);
}
