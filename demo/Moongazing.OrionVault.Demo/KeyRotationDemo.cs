namespace Moongazing.OrionVault.Demo;

using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;

/// <summary>
/// Demo 3: key rotation. OrionVault is multi-key read, single-key write. We first encrypt
/// under key 1, then stand up a second host that registers BOTH key 1 and key 2 with
/// <c>ActiveKeyId = 2</c>. The new host:
/// <list type="bullet">
///   <item><description>decrypts the legacy key-1 ciphertext (key 1 is still registered),</description></item>
///   <item><description>re-encrypts the value under key 2 (the new active key).</description></item>
/// </list>
/// The key id is read from the 2-byte ciphertext header, which is what makes online
/// rotation work without re-encrypting every historical row up front.
/// </summary>
internal static class KeyRotationDemo
{
    public static void Run()
    {
        DemoConsole.Section(3, "Key rotation (decrypt old key, re-encrypt under new key)");

        // --- Host A: only key 1 exists, active key is 1. ---
        using var hostV1 = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(DemoKeys.KeyIdV1, DemoKeys.KeyV1));
                o.ActiveKeyId = DemoKeys.KeyIdV1;
            })
            .Services
            .BuildServiceProvider();

        const string secret = "TR00 0006 1005 1978 6457 8413 26";
        byte[] legacyCiphertext = hostV1.GetRequiredService<IEncryptor>().EncryptString(secret);
        DemoConsole.Item("Original plaintext", secret);
        DemoConsole.Item("Encrypted under keyId", HeaderKeyId(legacyCiphertext).ToString(System.Globalization.CultureInfo.InvariantCulture));
        DemoConsole.Item("Legacy ciphertext", DemoConsole.ShortB64(legacyCiphertext));

        // --- Host B: key 1 AND key 2 registered, active key is 2. ---
        using var hostV2 = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k =>
                {
                    k.Add(DemoKeys.KeyIdV1, DemoKeys.KeyV1); // keep the old key so old rows still read
                    k.Add(DemoKeys.KeyIdV2, DemoKeys.KeyV2); // new key for new writes
                });
                o.ActiveKeyId = DemoKeys.KeyIdV2;
            })
            .Services
            .BuildServiceProvider();

        var rotatedEncryptor = hostV2.GetRequiredService<IEncryptor>();

        // Step 1: the new host can still read the old key-1 ciphertext.
        string recovered = rotatedEncryptor.DecryptString(legacyCiphertext);
        DemoConsole.Ok($"New host decrypted legacy key-1 ciphertext: \"{recovered}\"");

        // Step 2: re-encrypt the recovered value. The active key is now 2.
        byte[] rotatedCiphertext = rotatedEncryptor.EncryptString(recovered);
        DemoConsole.Item("Re-encrypted under keyId", HeaderKeyId(rotatedCiphertext).ToString(System.Globalization.CultureInfo.InvariantCulture));
        DemoConsole.Item("Rotated ciphertext", DemoConsole.ShortB64(rotatedCiphertext));

        // Step 3: prove the rotated ciphertext still decrypts to the original value.
        string finalValue = rotatedEncryptor.DecryptString(rotatedCiphertext);

        if (HeaderKeyId(legacyCiphertext) == DemoKeys.KeyIdV1
            && HeaderKeyId(rotatedCiphertext) == DemoKeys.KeyIdV2
            && finalValue == secret)
        {
            DemoConsole.Ok("Rotation complete: value preserved, header keyId advanced 1 -> 2.");
        }
        else
        {
            DemoConsole.Note("Unexpected: rotation invariant did not hold.");
        }
    }

    private static short HeaderKeyId(byte[] ciphertext)
        => (short)((ciphertext[0] << 8) | ciphertext[1]);
}
