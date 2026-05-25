namespace Moongazing.OrionVault.Options;

using Moongazing.OrionVault.Exceptions;

public sealed class StaticKeysBuilder
{
    private readonly Dictionary<short, byte[]> _keys = new();

    public StaticKeysBuilder Add(short keyId, string base64Key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(base64Key);
        if (_keys.ContainsKey(keyId))
            throw new OrionVaultConfigurationException(
                $"Duplicate key id {keyId} in StaticKeysBuilder.");

        byte[] bytes;
        try { bytes = Convert.FromBase64String(base64Key); }
        catch (FormatException ex)
        {
            throw new OrionVaultConfigurationException(
                $"Key {keyId} is not valid base64.", ex);
        }

        if (bytes.Length != 32)
            throw new OrionVaultConfigurationException(
                $"Key {keyId} decoded to {bytes.Length} bytes; expected 32 bytes (256-bit AES key).");

        _keys[keyId] = bytes;
        return this;
    }

    internal IReadOnlyDictionary<short, byte[]> Build() => _keys;
}
