namespace Moongazing.OrionVault.Benchmarks;

using System.Security.Cryptography;
using Moongazing.OrionVault.Abstractions;

/// <summary>
/// In-memory, allocation-free <see cref="IKeyProvider"/> used by every benchmark so the
/// measured path stays inside the AES-256-GCM core and never touches a database, AWS KMS,
/// or Azure Key Vault. A single 32-byte key is generated once at construction and returned
/// from a field, so key resolution cost is a dictionary-free reference read and does not
/// pollute the encrypt/decrypt timings.
/// </summary>
internal sealed class BenchmarkKeyProvider : IKeyProvider
{
    private readonly ReadOnlyMemory<byte> _key;

    public BenchmarkKeyProvider(short activeKeyId = 1)
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        _key = key;
        ActiveKeyId = activeKeyId;
    }

    public short ActiveKeyId { get; }

    public int KeyCount => 1;

    public ReadOnlyMemory<byte>? TryGetKey(short keyId)
        => keyId == ActiveKeyId ? _key : null;
}
