namespace Moongazing.OrionVault.Demo;

using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;

/// <summary>
/// Demo 1: the simplest possible use of the cipher. Build an <see cref="IEncryptor"/>
/// over a single in-memory key, encrypt a value, show the ciphertext layout, then
/// decrypt it back to the original plaintext.
/// </summary>
internal static class EncryptRoundTripDemo
{
    public static void Run()
    {
        DemoConsole.Section(1, "Encrypt / decrypt round-trip (single key)");

        using var provider = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(DemoKeys.KeyIdV1, DemoKeys.KeyV1));
                o.ActiveKeyId = DemoKeys.KeyIdV1;
            })
            .Services
            .BuildServiceProvider();

        var encryptor = provider.GetRequiredService<IEncryptor>();

        const string plaintext = "ali@example.com";
        DemoConsole.Item("Plaintext", plaintext);
        DemoConsole.Item("Plaintext length", $"{System.Text.Encoding.UTF8.GetByteCount(plaintext)} bytes");

        byte[] ciphertext = encryptor.EncryptString(plaintext);

        // On-disk layout is [keyId:2 | nonce:12 | tag:16 | ciphertext:N], 30-byte header.
        short keyId = (short)((ciphertext[0] << 8) | ciphertext[1]);
        DemoConsole.Item("Ciphertext (base64)", DemoConsole.ShortB64(ciphertext));
        DemoConsole.Item("Ciphertext length", $"{ciphertext.Length} bytes (30 header + {ciphertext.Length - 30} body)");
        DemoConsole.Item("Header keyId (BE)", keyId.ToString(System.Globalization.CultureInfo.InvariantCulture));

        string roundTripped = encryptor.DecryptString(ciphertext);
        DemoConsole.Item("Decrypted", roundTripped);

        if (roundTripped == plaintext)
            DemoConsole.Ok("Round-trip succeeded: decrypted value equals the original.");
        else
            DemoConsole.Note("MISMATCH: decrypted value does not equal the original.");
    }
}
