namespace Moongazing.OrionVault.Tests;

using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Rotation;
using Xunit;

public sealed class EncryptionRotatorTests
{
    private static IEncryptor Encryptor(short activeKeyId, params (short id, byte[] key)[] keys)
    {
        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k =>
            {
                foreach (var (id, key) in keys)
                {
                    k.Add(id, Convert.ToBase64String(key));
                }
            });
            o.ActiveKeyId = activeKeyId;
        });
        var sp = services.BuildServiceProvider();
        return sp.GetRequiredService<IEncryptor>();
    }

    private static byte[] NewKey() => RandomNumberGenerator.GetBytes(32);

    [Fact]
    public void NeedsRotation_returns_true_when_ciphertext_key_id_differs_from_active()
    {
        var key1 = NewKey();
        var key2 = NewKey();

        // Encrypt under key 1 (active id = 1).
        var encUnder1 = Encryptor(activeKeyId: 1, (1, key1));
        var ct = encUnder1.EncryptBytes(new byte[] { 0xAA, 0xBB });

        // Asked whether rotation is needed against active id = 2.
        Assert.True(EncryptionRotator.NeedsRotation(ct, activeKeyId: 2));
    }

    [Fact]
    public void NeedsRotation_returns_false_when_already_on_active_key()
    {
        var encUnder1 = Encryptor(activeKeyId: 1, (1, NewKey()));
        var ct = encUnder1.EncryptBytes(new byte[] { 1, 2, 3 });

        Assert.False(EncryptionRotator.NeedsRotation(ct, activeKeyId: 1));
    }

    [Fact]
    public void NeedsRotation_returns_false_for_under_header_length_input()
    {
        Assert.False(EncryptionRotator.NeedsRotation(new byte[] { 0x01 }, activeKeyId: 1));
        Assert.False(EncryptionRotator.NeedsRotation(Array.Empty<byte>(), activeKeyId: 1));
    }

    [Fact]
    public void Rotate_decrypts_under_old_key_then_re_encrypts_under_active()
    {
        var key1 = NewKey();
        var key2 = NewKey();
        var plaintext = new byte[] { 1, 2, 3, 4, 5 };

        // Initial encryption under key 1.
        var encUnder1 = Encryptor(activeKeyId: 1, (1, key1));
        var ct = encUnder1.EncryptBytes(plaintext);

        // Build an encryptor that knows BOTH keys (1 + 2) and has 2 as active.
        var rotator = Encryptor(activeKeyId: 2, (1, key1), (2, key2));
        var rotated = EncryptionRotator.Rotate(rotator, ct);

        // Rotated ciphertext should:
        //   (a) decrypt back to the original plaintext under the rotator (which has key 2)
        //   (b) NOT need further rotation against active id 2
        Assert.Equal(plaintext, rotator.DecryptBytes(rotated));
        Assert.False(EncryptionRotator.NeedsRotation(rotated, activeKeyId: 2));
    }

    [Fact]
    public void RotateString_round_trips_a_utf8_string_column()
    {
        var rotator = Encryptor(activeKeyId: 2, (1, NewKey()), (2, NewKey()));
        var ct = rotator.EncryptString("hello world");

        var rotated = EncryptionRotator.RotateString(rotator, ct);

        Assert.Equal("hello world", rotator.DecryptString(rotated));
    }

    [Fact]
    public void Rotate_rejects_null_arguments()
    {
        Assert.Throws<ArgumentNullException>(() =>
            EncryptionRotator.Rotate(null!, new byte[10]));
        var encryptor = Encryptor(activeKeyId: 1, (1, NewKey()));
        Assert.Throws<ArgumentNullException>(() =>
            EncryptionRotator.Rotate(encryptor, null!));
        Assert.Throws<ArgumentNullException>(() =>
            EncryptionRotator.NeedsRotation(null!, 1));
    }
}
