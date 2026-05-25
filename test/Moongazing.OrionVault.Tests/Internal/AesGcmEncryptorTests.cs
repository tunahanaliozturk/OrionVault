namespace Moongazing.OrionVault.Tests.Internal;

using FluentAssertions;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.Exceptions;
using Moongazing.OrionVault.Internal;
using Xunit;

public class AesGcmEncryptorTests
{
    private static readonly byte[] Key1 = new byte[32];
    private static readonly byte[] Key2 = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly OrionVaultDiagnostics Diag = new();

    private sealed class FixedKeys : IKeyProvider
    {
        private readonly Dictionary<short, byte[]> _keys;
        public FixedKeys(short active, params (short id, byte[] key)[] keys)
        {
            ActiveKeyId = active;
            _keys = keys.ToDictionary(k => k.id, k => k.key);
        }
        public short ActiveKeyId { get; }
        public ReadOnlyMemory<byte>? TryGetKey(short keyId)
            => _keys.TryGetValue(keyId, out var k) ? k : null;
    }

    [Fact]
    public void EncryptString_then_DecryptString_round_trips()
    {
        var sut = new AesGcmEncryptor(new FixedKeys(1, (1, Key1)), Diag);

        var ciphertext = sut.EncryptString("hello world");
        var plaintext = sut.DecryptString(ciphertext);

        plaintext.Should().Be("hello world");
        ciphertext.Length.Should().Be(30 + System.Text.Encoding.UTF8.GetByteCount("hello world"));
        ciphertext[0].Should().Be(0);
        ciphertext[1].Should().Be(1);
    }

    [Fact]
    public void EncryptString_with_empty_string_produces_30_byte_ciphertext()
    {
        var sut = new AesGcmEncryptor(new FixedKeys(1, (1, Key1)), Diag);

        var ciphertext = sut.EncryptString("");

        ciphertext.Length.Should().Be(30);
        sut.DecryptString(ciphertext).Should().Be("");
    }

    [Fact]
    public void EncryptBytes_round_trips_with_DecryptBytes()
    {
        var sut = new AesGcmEncryptor(new FixedKeys(1, (1, Key1)), Diag);
        var payload = new byte[] { 1, 2, 3, 4, 5 };

        var ciphertext = sut.EncryptBytes(payload);

        sut.DecryptBytes(ciphertext).Should().Equal(payload);
    }

    [Fact]
    public void Encrypt_uses_ActiveKeyId_for_new_writes()
    {
        var sut = new AesGcmEncryptor(new FixedKeys(active: 2, (1, Key1), (2, Key2)), Diag);

        var ciphertext = sut.EncryptString("x");

        CipherFormat.ReadKeyId(ciphertext).Should().Be(2);
    }

    [Fact]
    public void Decrypt_reads_old_key_for_legacy_ciphertext()
    {
        var sutOld = new AesGcmEncryptor(new FixedKeys(active: 1, (1, Key1)), Diag);
        var legacy = sutOld.EncryptString("oldvalue");

        var sutNew = new AesGcmEncryptor(new FixedKeys(active: 2, (1, Key1), (2, Key2)), Diag);

        sutNew.DecryptString(legacy).Should().Be("oldvalue");
    }

    [Fact]
    public void Decrypt_throws_on_tampering()
    {
        var sut = new AesGcmEncryptor(new FixedKeys(1, (1, Key1)), Diag);
        var ciphertext = sut.EncryptString("important");

        ciphertext[^1] ^= 0x01;

        var act = () => sut.DecryptString(ciphertext);
        act.Should().Throw<OrionVaultDecryptionException>();
    }

    [Fact]
    public void Decrypt_throws_OrionVaultKeyNotFoundException_for_unknown_key_id()
    {
        var encWithKey2 = new AesGcmEncryptor(new FixedKeys(active: 2, (2, Key2)), Diag);
        var ciphertext = encWithKey2.EncryptString("x");

        var encMissingKey2 = new AesGcmEncryptor(new FixedKeys(active: 1, (1, Key1)), Diag);

        var act = () => encMissingKey2.DecryptString(ciphertext);
        act.Should().Throw<OrionVaultKeyNotFoundException>()
            .Where(e => e.KeyId == 2);
    }

    [Fact]
    public void Decrypt_throws_on_too_short_ciphertext()
    {
        var sut = new AesGcmEncryptor(new FixedKeys(1, (1, Key1)), Diag);

        var act = () => sut.DecryptString(new byte[10]);
        act.Should().Throw<OrionVaultDecryptionException>();
    }

    [Fact]
    public void EncryptString_uses_fresh_random_nonce_each_call()
    {
        var sut = new AesGcmEncryptor(new FixedKeys(1, (1, Key1)), Diag);

        var a = sut.EncryptString("same");
        var b = sut.EncryptString("same");

        a.Should().NotEqual(b);
    }
}
