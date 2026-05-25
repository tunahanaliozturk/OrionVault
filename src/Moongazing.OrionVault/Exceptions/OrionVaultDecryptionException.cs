namespace Moongazing.OrionVault.Exceptions;

/// <summary>
/// Thrown when decryption of a stored ciphertext fails. Reasons include tampered
/// ciphertext (authentication tag mismatch), malformed ciphertext (too short or
/// invalid header), or unknown key id (see <see cref="OrionVaultKeyNotFoundException"/>).
/// </summary>
public class OrionVaultDecryptionException : Exception
{
    public OrionVaultDecryptionException() { }

    public OrionVaultDecryptionException(string message) : base(message) { }

    public OrionVaultDecryptionException(string message, Exception innerException)
        : base(message, innerException) { }
}
