namespace Moongazing.OrionVault.HashiCorpVault;

/// <summary>
/// Narrow abstraction over the HashiCorp Vault transit-engine decrypt call. Exists so the provider
/// can be unit-tested without a real Vault server; the production implementation forwards to
/// <c>IVaultClient.V1.Secrets.Transit.DecryptAsync</c> against the configured transit key and mount
/// point.
/// </summary>
public interface IVaultTransitDecryptClient
{
    /// <summary>
    /// Decrypt a single wrapped data key. Unlike the AWS / Azure / GCP providers (whose wrapped
    /// value is an opaque base64 blob), a Vault transit "ciphertext" is the engine's own
    /// <c>vault:v1:...</c> string, so this seam takes the ciphertext as a string rather than bytes.
    /// </summary>
    /// <param name="ciphertext">The Vault transit ciphertext, e.g. <c>vault:v1:abc123==</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The plaintext data key bytes.</returns>
    /// <remarks>
    /// Implementations should propagate transport / Vault errors to the caller; OrionVault surfaces
    /// them as <see cref="Moongazing.OrionVault.Exceptions.OrionVaultConfigurationException"/> at
    /// startup so a misconfigured deployment fails fast.
    /// </remarks>
    Task<byte[]> DecryptAsync(string ciphertext, CancellationToken cancellationToken);
}
