namespace Moongazing.OrionVault.AzureKeyVault;

/// <summary>
/// Narrow abstraction over the Azure Key Vault unwrap call. Exists so the provider can be
/// unit-tested without spinning up a real <c>CryptographyClient</c>; the production
/// implementation forwards to <c>CryptographyClient.UnwrapKey</c>.
/// </summary>
public interface IKeyVaultUnwrapClient
{
    /// <summary>
    /// Unwrap a single wrapped data key. Implementations should propagate transport / vault
    /// errors to the caller; OrionVault surfaces them as
    /// <see cref="Moongazing.OrionVault.Exceptions.OrionVaultConfigurationException"/> at
    /// startup so a misconfigured deployment fails fast.
    /// </summary>
    /// <param name="encryptedKey">Wrapped data-key bytes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The plaintext data key.</returns>
    Task<byte[]> UnwrapAsync(byte[] encryptedKey, CancellationToken cancellationToken);
}
