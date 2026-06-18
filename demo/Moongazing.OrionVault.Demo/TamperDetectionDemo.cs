namespace Moongazing.OrionVault.Demo;

using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Exceptions;

/// <summary>
/// Demo 4: tamper detection. AES-256-GCM is an AEAD cipher: every decrypt verifies the
/// 128-bit authentication tag. We flip a single bit in the ciphertext body and in the
/// authentication tag; both decrypts fail with <see cref="OrionVaultDecryptionException"/>
/// rather than returning silently-corrupted plaintext. We also show that referencing an
/// unregistered key id raises <see cref="OrionVaultKeyNotFoundException"/>.
/// </summary>
internal static class TamperDetectionDemo
{
    public static void Run()
    {
        DemoConsole.Section(4, "Tamper detection (authentication tag mismatch)");

        using var provider = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(DemoKeys.KeyIdV1, DemoKeys.KeyV1));
                o.ActiveKeyId = DemoKeys.KeyIdV1;
            })
            .Services
            .BuildServiceProvider();

        var encryptor = provider.GetRequiredService<IEncryptor>();

        const string plaintext = "4111 1111 1111 1111";
        byte[] ciphertext = encryptor.EncryptString(plaintext);
        DemoConsole.Item("Plaintext", plaintext);
        DemoConsole.Item("Genuine ciphertext", DemoConsole.ShortB64(ciphertext));
        DemoConsole.Ok($"Untampered decrypt returns: \"{encryptor.DecryptString(ciphertext)}\"");

        // --- Tamper 1: flip a bit in the ciphertext body (everything past the 30-byte header). ---
        byte[] bodyTampered = (byte[])ciphertext.Clone();
        bodyTampered[^1] ^= 0x01;
        TryDecryptExpectingFailure(encryptor, bodyTampered, "ciphertext body bit flip");

        // --- Tamper 2: flip a bit inside the 16-byte authentication tag (bytes 14..29). ---
        byte[] tagTampered = (byte[])ciphertext.Clone();
        tagTampered[14] ^= 0x80;
        TryDecryptExpectingFailure(encryptor, tagTampered, "authentication tag bit flip");

        // --- Tamper 3: rewrite the header keyId to an unregistered key (99). ---
        byte[] keyTampered = (byte[])ciphertext.Clone();
        keyTampered[0] = 0x00;
        keyTampered[1] = 0x63; // 99 big-endian
        TryDecryptExpectingFailure(encryptor, keyTampered, "unregistered keyId in header");
    }

    private static void TryDecryptExpectingFailure(IEncryptor encryptor, byte[] tampered, string description)
    {
        try
        {
            string result = encryptor.DecryptString(tampered);
            DemoConsole.Note($"SECURITY HOLE: {description} decrypted to \"{result}\" instead of throwing.");
        }
        catch (OrionVaultKeyNotFoundException ex)
        {
            DemoConsole.Caught($"{description} -> OrionVaultKeyNotFoundException (keyId {ex.KeyId}).");
        }
        catch (OrionVaultDecryptionException)
        {
            DemoConsole.Caught($"{description} -> OrionVaultDecryptionException. Corrupted plaintext was NOT returned.");
        }
    }
}
