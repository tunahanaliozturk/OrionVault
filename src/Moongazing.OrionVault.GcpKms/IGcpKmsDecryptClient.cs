namespace Moongazing.OrionVault.GcpKms;

/// <summary>
/// Narrow abstraction over the Google Cloud KMS decrypt call. Exists so the provider can be
/// unit-tested without a real <c>KeyManagementServiceClient</c> / network; the production
/// implementation forwards to <c>KeyManagementServiceClient.DecryptAsync</c> against the supplied
/// crypto-key resource name.
/// </summary>
public interface IGcpKmsDecryptClient
{
    /// <summary>
    /// Decrypt a single wrapped data key against the supplied crypto-key resource name.
    /// </summary>
    /// <param name="cryptoKeyName">
    /// The fully-qualified Cloud KMS crypto-key resource name to decrypt under (the validated
    /// <see cref="GcpKmsKeyProviderOptions.CryptoKeyName"/>). Passed per call so the key name the
    /// provider validated is the exact name that reaches the Decrypt request, rather than a name
    /// captured separately at adapter-construction time.
    /// </param>
    /// <param name="ciphertext">The KMS ciphertext blob.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The plaintext data key.</returns>
    /// <remarks>
    /// Implementations should propagate transport / KMS errors to the caller; a revocation-class
    /// denial (key disabled / revoked / not-found / permission denied) should surface so the
    /// provider can translate it into a
    /// <see cref="Moongazing.OrionVault.Exceptions.KeyUnwrapException"/> for the envelope-key cache,
    /// and OrionVault surfaces a startup failure as
    /// <see cref="Moongazing.OrionVault.Exceptions.OrionVaultConfigurationException"/> so a
    /// misconfigured deployment fails fast.
    /// </remarks>
    Task<byte[]> DecryptAsync(string cryptoKeyName, byte[] ciphertext, CancellationToken cancellationToken);
}
