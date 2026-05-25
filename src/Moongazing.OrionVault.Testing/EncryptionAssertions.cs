namespace Moongazing.OrionVault.Testing;

using Moongazing.OrionVault.Internal;

/// <summary>
/// Assertion helpers that inspect raw column bytes produced by OrionVault.
/// Throws <see cref="Xunit.Sdk.XunitException"/> so failures show up as
/// regular xUnit assertion failures.
/// </summary>
public static class EncryptionAssertions
{
    public static void IsEncrypted(byte[] columnValue)
    {
        ArgumentNullException.ThrowIfNull(columnValue);
        if (columnValue.Length < CipherFormat.MinimumCiphertextLength)
        {
            throw new Xunit.Sdk.XunitException(
                $"Expected encrypted column (>= {CipherFormat.MinimumCiphertextLength} bytes), got {columnValue.Length} bytes.");
        }
    }

    public static short ReadKeyId(byte[] columnValue)
    {
        IsEncrypted(columnValue);
        return CipherFormat.ReadKeyId(columnValue);
    }

    public static void IsEncryptedWithKey(byte[] columnValue, short expectedKeyId)
    {
        var actual = ReadKeyId(columnValue);
        if (actual != expectedKeyId)
        {
            throw new Xunit.Sdk.XunitException(
                $"Expected encrypted with key id {expectedKeyId}, got {actual}.");
        }
    }
}
