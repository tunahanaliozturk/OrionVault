namespace Moongazing.OrionVault.Testing;

using System.Collections.Concurrent;
using Moongazing.OrionVault.Abstractions;

/// <summary>
/// Deterministic <see cref="IKeyProvider"/> for tests. Defaults to a single
/// 32-byte zero key under id 1. Add additional keys with <see cref="Add"/>.
/// Use <see cref="Default"/> for the common single-key case.
/// </summary>
public sealed class TestKeyProvider : IKeyProvider
{
    private readonly ConcurrentDictionary<short, byte[]> keys = new();

    public TestKeyProvider(short activeKeyId = 1)
    {
        ActiveKeyId = activeKeyId;
        keys[activeKeyId] = new byte[32];
    }

    public static TestKeyProvider Default { get; } = new(activeKeyId: 1);

    public short ActiveKeyId { get; }

    public void Add(short keyId, ReadOnlyMemory<byte> key)
    {
        if (key.Length != 32)
        {
            throw new ArgumentException("Key must be exactly 32 bytes.", nameof(key));
        }

        keys[keyId] = key.ToArray();
    }

    public ReadOnlyMemory<byte>? TryGetKey(short keyId)
    {
        if (keys.TryGetValue(keyId, out var k))
        {
            return k;
        }

        return null;
    }
}
