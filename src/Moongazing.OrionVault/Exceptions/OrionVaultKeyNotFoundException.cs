namespace Moongazing.OrionVault.Exceptions;

/// <summary>
/// Thrown when the ciphertext references a key id not present in the configured
/// <see cref="Abstractions.IKeyProvider"/>. Typical cause: a key was rotated out
/// while values encrypted with it are still in the database.
/// </summary>
public sealed class OrionVaultKeyNotFoundException : OrionVaultDecryptionException
{
    public short KeyId { get; }

    public OrionVaultKeyNotFoundException() { }

    public OrionVaultKeyNotFoundException(string message) : base(message) { }

    public OrionVaultKeyNotFoundException(string message, Exception innerException)
        : base(message, innerException) { }

    public OrionVaultKeyNotFoundException(short keyId)
        : base($"OrionVault key id {keyId} was not found in the configured IKeyProvider.")
    {
        KeyId = keyId;
    }
}
