namespace Moongazing.OrionVault.Internal;

using Moongazing.OrionVault.Abstractions;

internal sealed class StaticKeyProvider : IKeyProvider
{
    private readonly IReadOnlyDictionary<short, byte[]> _keys;

    public StaticKeyProvider(IReadOnlyDictionary<short, byte[]> keys, short activeKeyId)
    {
        _keys = keys;
        ActiveKeyId = activeKeyId;
    }

    public short ActiveKeyId { get; }

    public ReadOnlyMemory<byte>? TryGetKey(short keyId)
    {
        if (_keys.TryGetValue(keyId, out var k)) return k;
        return null;
    }
}
