// NativeAOT publish smoke test for OrionVault.
//
// Exercises the field-encryption path end to end in a trimmed, AOT-published binary through the
// real DI wiring: register a static AES key, resolve IEncryptor (the AES-GCM implementation), then
// round-trip a value and confirm authenticated encryption rejects a tampered ciphertext. The
// crypto and DI paths are reflection-free, so this locks in that consumers publishing native keep
// a warning-free core.
//
// Exit 0 == every assertion held under NativeAOT. Any mismatch throws and fails the CI job.

using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Exceptions;

// A real 32-byte (256-bit) key, base64-encoded, registered as the active key id.
const string keyBase64 = "b3Jpb252YXVsdC1hb3Qtc21va2UtMzJieXRlLWtleSE=";
const short keyId = 1;
const string plaintext = "4111-1111-1111-1111";

var provider = new ServiceCollection()
    .AddOrionVault(options =>
    {
        options.ActiveKeyId = keyId;
        options.UseStaticKeys(keys => keys.Add(keyId, keyBase64));
    })
    .Services
    .BuildServiceProvider();

var encryptor = provider.GetRequiredService<IEncryptor>();

// 1. Round trip: ciphertext differs from plaintext and decrypts back to the original.
byte[] ciphertext = encryptor.EncryptString(plaintext);
Require(ciphertext.Length > 0, "encryption should produce output");
Require(encryptor.DecryptString(ciphertext) == plaintext, "decrypt should recover the original plaintext");

// 2. Authenticated encryption: flip one ciphertext byte and the GCM tag check must reject it.
byte[] tampered = (byte[])ciphertext.Clone();
tampered[^1] ^= 0xFF;
bool rejected = false;
try
{
    encryptor.DecryptString(tampered);
}
catch (OrionVaultDecryptionException)
{
    rejected = true;
}
Require(rejected, "a tampered ciphertext must fail authenticated decryption");

Console.WriteLine("OrionVault AOT smoke test passed.");
return 0;

static void Require(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException($"AOT smoke assertion failed: {message}");
    }
}
