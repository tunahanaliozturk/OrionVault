namespace Moongazing.OrionVault.Exceptions;

/// <summary>
/// Thrown when OrionVault is misconfigured — invalid key bytes, duplicate key id,
/// <c>ActiveKeyId</c> not registered, <c>[Encrypted]</c> on an unsupported type, etc.
/// Raised at startup or model build, never at runtime decrypt.
/// </summary>
public sealed class OrionVaultConfigurationException : Exception
{
    public OrionVaultConfigurationException() { }

    public OrionVaultConfigurationException(string message) : base(message) { }

    public OrionVaultConfigurationException(string message, Exception innerException)
        : base(message, innerException) { }
}
