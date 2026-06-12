namespace Moongazing.OrionVault.Abstractions;

/// <summary>
/// v0.2.23 consumer-supplied observer invoked on EVERY successful encrypt and decrypt.
/// Useful for compliance regimes that require an audit trail of cryptographic
/// operations (which key was used, when, by which call site if available via Activity
/// context) without coupling the audit logic to the load-bearing AES path.
/// </summary>
/// <remarks>
/// <para>
/// The observer fires AFTER the operation succeeds, BEFORE the result returns to the
/// caller. A throwing observer does NOT roll back the operation - encrypt has already
/// produced ciphertext, decrypt has already produced plaintext. Observer exceptions
/// are caught and swallowed so an audit-side outage cannot disrupt the cryptographic
/// path.
/// </para>
/// <para>
/// No observer is registered by default. Consumers wire one via
/// <c>services.AddSingleton&lt;IEncryptionAuditObserver, MyAuditObserver&gt;()</c>.
/// </para>
/// </remarks>
public interface IEncryptionAuditObserver
{
    /// <summary>Notify the observer of a successful encrypt.</summary>
    /// <param name="keyId">Key id used for the encrypt.</param>
    /// <param name="plaintextLength">Plaintext byte length (input).</param>
    /// <param name="ciphertextLength">Ciphertext byte length (output).</param>
    void OnEncrypted(short keyId, int plaintextLength, int ciphertextLength);

    /// <summary>Notify the observer of a successful decrypt.</summary>
    /// <param name="keyId">Key id used for the decrypt.</param>
    /// <param name="ciphertextLength">Ciphertext byte length (input).</param>
    /// <param name="plaintextLength">Plaintext byte length (output).</param>
    void OnDecrypted(short keyId, int ciphertextLength, int plaintextLength);
}

/// <summary>Default no-op observer used when no consumer-registered observer is present.</summary>
public sealed class NullEncryptionAuditObserver : IEncryptionAuditObserver
{
    /// <inheritdoc />
    public void OnEncrypted(short keyId, int plaintextLength, int ciphertextLength)
    {
        // no-op
    }

    /// <inheritdoc />
    public void OnDecrypted(short keyId, int ciphertextLength, int plaintextLength)
    {
        // no-op
    }
}
