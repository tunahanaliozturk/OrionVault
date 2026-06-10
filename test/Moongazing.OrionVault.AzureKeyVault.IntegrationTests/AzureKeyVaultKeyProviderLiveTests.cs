namespace Moongazing.OrionVault.AzureKeyVault.IntegrationTests;

using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Moongazing.OrionVault.AzureKeyVault;
using Xunit;

/// <summary>
/// Live Azure Key Vault integration tests. Skipped locally unless the consumer sets the
/// required environment variables:
/// <list type="bullet">
///   <item><description><c>ORIONVAULT_AZURE_KEYVAULT_URI</c> - e.g. <c>https://my-vault.vault.azure.net/</c>.</description></item>
///   <item><description><c>ORIONVAULT_AZURE_KEYVAULT_KEY_NAME</c> - an existing RSA key in the vault (the test wraps a 32-byte AES key with it).</description></item>
/// </list>
/// Credentials flow through <see cref="DefaultAzureCredential"/> so any of the standard
/// chain entries work (managed identity, Azure CLI, env-var, VS / VSCode sign-in).
/// </summary>
/// <remarks>
/// Key Vault has no widely-available local emulator (Azurite covers Storage but not Key
/// Vault). These tests are therefore CONDITIONAL on consumer-supplied credentials; the
/// LocalStack-backed AwsKms suite provides the on-CI integration coverage for the same
/// provider contract.
/// </remarks>
[Trait("Category", "Integration")]
public sealed class AzureKeyVaultKeyProviderLiveTests
{
    private static readonly string? VaultUri = Environment.GetEnvironmentVariable("ORIONVAULT_AZURE_KEYVAULT_URI");
    private static readonly string? KeyName = Environment.GetEnvironmentVariable("ORIONVAULT_AZURE_KEYVAULT_KEY_NAME");
    public static bool IsConfigured => !string.IsNullOrEmpty(VaultUri) && !string.IsNullOrEmpty(KeyName);
    private const string SkipReason = "Set ORIONVAULT_AZURE_KEYVAULT_URI + ORIONVAULT_AZURE_KEYVAULT_KEY_NAME to run.";

    private static byte[] Key32(byte fill)
    {
        var bytes = new byte[32];
        Array.Fill(bytes, fill);
        return bytes;
    }

    private static (KeyClient keyClient, CryptographyClient cryptoClient) BuildClients()
    {
        var credential = new DefaultAzureCredential();
        var keyClient = new KeyClient(new Uri(VaultUri!), credential);
        var key = keyClient.GetKey(KeyName);
        var cryptoClient = new CryptographyClient(key.Value.Id, credential);
        return (keyClient, cryptoClient);
    }

    private static async Task<string> WrapAsync(CryptographyClient cryptoClient, byte[] plaintext)
    {
        var result = await cryptoClient.WrapKeyAsync(KeyWrapAlgorithm.RsaOaep256, plaintext);
        return Convert.ToBase64String(result.EncryptedKey);
    }

    [SkippableFact]
    public async Task CreateAsync_unwraps_two_keys_against_live_KeyVault()
    {
        Skip.IfNot(IsConfigured, SkipReason);

        var (keyClient, cryptoClient) = BuildClients();
        var keyOne = Key32(0x11);
        var keyTwo = Key32(0x22);

        var options = new AzureKeyVaultKeyProviderOptions
        {
            KeyName = KeyName!,
            ActiveKeyId = 2,
        };
        options.WrappedKeys[1] = await WrapAsync(cryptoClient, keyOne);
        options.WrappedKeys[2] = await WrapAsync(cryptoClient, keyTwo);

        var unwrap = new LiveUnwrapAdapter(cryptoClient, options.WrapAlgorithm);
        var provider = await AzureKeyVaultKeyProvider.CreateAsync(unwrap, options);

        Assert.Equal(2, provider.ActiveKeyId);
        Assert.True(keyOne.AsSpan().SequenceEqual(provider.TryGetKey(1)!.Value.Span));
        Assert.True(keyTwo.AsSpan().SequenceEqual(provider.TryGetKey(2)!.Value.Span));
    }

    [SkippableFact]
    public async Task CreateAsync_rejects_wrong_length_plaintext_against_live_KeyVault()
    {
        Skip.IfNot(IsConfigured, SkipReason);

        var (keyClient, cryptoClient) = BuildClients();
        var sixteen = new byte[16];
        Array.Fill(sixteen, (byte)0x33);

        var options = new AzureKeyVaultKeyProviderOptions
        {
            KeyName = KeyName!,
            ActiveKeyId = 1,
        };
        options.WrappedKeys[1] = await WrapAsync(cryptoClient, sixteen);

        var unwrap = new LiveUnwrapAdapter(cryptoClient, options.WrapAlgorithm);
        await Assert.ThrowsAsync<Moongazing.OrionVault.Exceptions.OrionVaultConfigurationException>(
            () => AzureKeyVaultKeyProvider.CreateAsync(unwrap, options));
    }

    private sealed class LiveUnwrapAdapter : IKeyVaultUnwrapClient
    {
        private readonly CryptographyClient client;
        private readonly KeyWrapAlgorithm algorithm;

        public LiveUnwrapAdapter(CryptographyClient client, KeyWrapAlgorithm algorithm)
        {
            this.client = client;
            this.algorithm = algorithm;
        }

        public async Task<byte[]> UnwrapAsync(byte[] encryptedKey, CancellationToken cancellationToken)
        {
            var response = await client.UnwrapKeyAsync(algorithm, encryptedKey, cancellationToken);
            return response.Key;
        }
    }
}

/// <summary>
/// Minimal skippable-fact polyfill so the test rendering matches xunit.skippablefact's
/// conventions without taking the package dependency. Throws <see cref="SkipException"/>
/// which xUnit reports as a skipped test result.
/// </summary>
internal sealed class SkippableFactAttribute : Xunit.FactAttribute { }

internal static class Skip
{
    public static void IfNot(bool condition, string reason)
    {
        if (!condition)
        {
            throw new SkipException(reason);
        }
    }
}

internal sealed class SkipException : Exception
{
    public SkipException() { }
    public SkipException(string reason) : base(reason) { }
    public SkipException(string message, Exception innerException) : base(message, innerException) { }
}
