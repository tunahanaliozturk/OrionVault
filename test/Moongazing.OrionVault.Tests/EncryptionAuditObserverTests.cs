namespace Moongazing.OrionVault.Tests;

using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Xunit;

public sealed class EncryptionAuditObserverTests
{
    private sealed class CapturingObserver : IEncryptionAuditObserver
    {
        public short LastEncryptKey;
        public int LastEncryptPlaintext;
        public int LastEncryptCiphertext;
        public short LastDecryptKey;
        public int LastDecryptCiphertext;
        public int LastDecryptPlaintext;

        public void OnEncrypted(short keyId, int plaintextLength, int ciphertextLength)
        {
            LastEncryptKey = keyId;
            LastEncryptPlaintext = plaintextLength;
            LastEncryptCiphertext = ciphertextLength;
        }

        public void OnDecrypted(short keyId, int ciphertextLength, int plaintextLength)
        {
            LastDecryptKey = keyId;
            LastDecryptCiphertext = ciphertextLength;
            LastDecryptPlaintext = plaintextLength;
        }
    }

    [Fact]
    public void NullEncryptionAuditObserver_methods_are_noops()
    {
        var sut = new NullEncryptionAuditObserver();
        sut.OnEncrypted(1, 100, 128);
        sut.OnDecrypted(1, 128, 100);
    }

    [Fact]
    public void Observer_receives_encrypt_and_decrypt_notifications()
    {
        var observer = new CapturingObserver();
        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(3, System.Convert.ToBase64String(
                System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))));
            o.ActiveKeyId = 3;
        });
        services.AddSingleton<IEncryptionAuditObserver>(observer);
        using var sp = services.BuildServiceProvider();

        var encryptor = sp.GetRequiredService<IEncryptor>();
        var plaintext = new byte[] { 1, 2, 3, 4, 5, 6, 7 };
        var ciphertext = encryptor.EncryptBytes(plaintext);
        var roundtripped = encryptor.DecryptBytes(ciphertext);

        Assert.Equal((short)3, observer.LastEncryptKey);
        Assert.Equal(plaintext.Length, observer.LastEncryptPlaintext);
        Assert.Equal(ciphertext.Length, observer.LastEncryptCiphertext);

        Assert.Equal((short)3, observer.LastDecryptKey);
        Assert.Equal(ciphertext.Length, observer.LastDecryptCiphertext);
        Assert.Equal(plaintext.Length, observer.LastDecryptPlaintext);
        Assert.Equal(plaintext, roundtripped);
    }
}
