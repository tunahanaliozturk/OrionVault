namespace Moongazing.OrionVault.Demo;

using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;

/// <summary>
/// Demo 2: AES-GCM is randomized. Encrypting the same plaintext twice draws a fresh
/// nonce each time, so the two ciphertexts differ even though both decrypt back to the
/// same value. This is why a plain SQL <c>WHERE col = @p</c> against an encrypted column
/// never matches (the analyzer flags this as OV0002).
/// </summary>
internal static class RandomizedCiphertextDemo
{
    public static void Run()
    {
        DemoConsole.Section(2, "Randomized ciphertext (fresh nonce per encryption)");

        using var provider = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(DemoKeys.KeyIdV1, DemoKeys.KeyV1));
                o.ActiveKeyId = DemoKeys.KeyIdV1;
            })
            .Services
            .BuildServiceProvider();

        var encryptor = provider.GetRequiredService<IEncryptor>();

        const string plaintext = "same-secret-value";
        byte[] first = encryptor.EncryptString(plaintext);
        byte[] second = encryptor.EncryptString(plaintext);

        DemoConsole.Item("Plaintext", plaintext);
        DemoConsole.Item("Ciphertext #1", DemoConsole.ShortB64(first));
        DemoConsole.Item("Ciphertext #2", DemoConsole.ShortB64(second));

        bool bytesEqual = first.AsSpan().SequenceEqual(second);
        DemoConsole.Item("Ciphertexts identical?", bytesEqual ? "yes" : "no");

        // Nonce is the 12 bytes immediately after the 2-byte keyId header.
        bool nonceEqual = first.AsSpan(2, 12).SequenceEqual(second.AsSpan(2, 12));
        DemoConsole.Item("Nonces identical?", nonceEqual ? "yes" : "no");

        bool bothDecrypt = encryptor.DecryptString(first) == plaintext
                        && encryptor.DecryptString(second) == plaintext;

        if (!bytesEqual && !nonceEqual && bothDecrypt)
            DemoConsole.Ok("Distinct ciphertexts, distinct nonces, both decrypt to the same plaintext.");
        else
            DemoConsole.Note("Unexpected: randomized-encryption invariant did not hold.");

        DemoConsole.Note("Consequence: do not WHERE-filter on an encrypted column; use an HMAC index column instead.");
    }
}
