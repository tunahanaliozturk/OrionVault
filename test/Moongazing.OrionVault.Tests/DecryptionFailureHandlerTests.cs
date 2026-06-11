namespace Moongazing.OrionVault.Tests;

using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Exceptions;
using Xunit;

public sealed class DecryptionFailureHandlerTests
{
    private sealed class CapturingHandler : IDecryptionFailureHandler
    {
        public string? CapturedReason { get; private set; }
        public short CapturedKeyId { get; private set; }
        public System.Exception? CapturedException { get; private set; }

        public void OnDecryptionFailed(string reason, short keyId, System.Exception exception)
        {
            CapturedReason = reason;
            CapturedKeyId = keyId;
            CapturedException = exception;
        }
    }

    [Fact]
    public void NullDecryptionFailureHandler_OnDecryptionFailed_is_a_noop()
    {
        var sut = new NullDecryptionFailureHandler();

        // Just verify no throw.
        sut.OnDecryptionFailed("tampered", keyId: 7, new System.InvalidOperationException("boom"));
    }

    [Fact]
    public void Handler_fires_on_tampered_ciphertext_with_correct_reason_tag()
    {
        var handler = new CapturingHandler();
        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, System.Convert.ToBase64String(
                System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))));
            o.ActiveKeyId = 1;
        });
        services.AddSingleton<IDecryptionFailureHandler>(handler);
        using var sp = services.BuildServiceProvider();
        var encryptor = sp.GetRequiredService<IEncryptor>();

        var ciphertext = encryptor.EncryptBytes(new byte[] { 1, 2, 3 });
        // Flip a byte in the tag region so AES-GCM authentication fails.
        ciphertext[ciphertext.Length - 1] ^= 0xff;

        Assert.Throws<OrionVaultDecryptionException>(() => encryptor.DecryptBytes(ciphertext));
        Assert.Equal("tampered", handler.CapturedReason);
    }
}
