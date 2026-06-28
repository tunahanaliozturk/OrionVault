namespace Moongazing.OrionVault.HashiCorpVault.IntegrationTests;

using Moongazing.OrionVault.HashiCorpVault;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.SecretsEngines.Transit;
using Xunit;

/// <summary>
/// Live HashiCorp Vault integration tests against the transit secrets engine. Skipped locally
/// unless the consumer sets the required environment variables:
/// <list type="bullet">
///   <item><description><c>ORIONVAULT_VAULT_ADDR</c> - e.g. <c>http://127.0.0.1:8200</c>.</description></item>
///   <item><description><c>ORIONVAULT_VAULT_TOKEN</c> - a token with transit encrypt / decrypt on the key.</description></item>
///   <item><description><c>ORIONVAULT_VAULT_TRANSIT_KEY</c> - an existing transit key name.</description></item>
/// </list>
/// </summary>
/// <remarks>
/// The transit engine and key are assumed to already exist (e.g. a dev-mode Vault with
/// <c>vault secrets enable transit</c> and <c>vault write -f transit/keys/orionvault</c>). These
/// tests are CONDITIONAL on consumer-supplied connection details, mirroring the Azure Key Vault
/// live suite; the mock-seam unit tests provide the on-CI coverage for the same provider contract.
/// </remarks>
[Trait("Category", "Integration")]
public sealed class HashiCorpVaultKeyProviderLiveTests
{
    private static readonly string? Addr = Environment.GetEnvironmentVariable("ORIONVAULT_VAULT_ADDR");
    private static readonly string? Token = Environment.GetEnvironmentVariable("ORIONVAULT_VAULT_TOKEN");
    private static readonly string? TransitKey = Environment.GetEnvironmentVariable("ORIONVAULT_VAULT_TRANSIT_KEY");

    public static bool IsConfigured =>
        !string.IsNullOrEmpty(Addr) && !string.IsNullOrEmpty(Token) && !string.IsNullOrEmpty(TransitKey);

    private const string MountPoint = "transit";

    private static byte[] Key32(byte fill)
    {
        var bytes = new byte[32];
        Array.Fill(bytes, fill);
        return bytes;
    }

    private static IVaultClient BuildClient()
        => new VaultClient(new VaultClientSettings(Addr!, new TokenAuthMethodInfo(Token!)));

    private static async Task<string> WrapAsync(IVaultClient client, byte[] plaintext)
    {
        var options = new EncryptRequestOptions
        {
            BatchedEncryptionItems = new List<EncryptionItem>
            {
                new() { Base64EncodedPlainText = Convert.ToBase64String(plaintext) },
            },
        };
        var response = await client.V1.Secrets.Transit.EncryptAsync(TransitKey!, options, MountPoint);
        return response.Data.BatchedResults.First().CipherText;
    }

    [Fact]
    public async Task CreateAsync_unwraps_two_keys_against_live_vault()
    {
        if (!IsConfigured)
        {
            return; // Vacuous pass when env vars are absent; the real assertion only runs live.
        }
        var client = BuildClient();
        var keyOne = Key32(0x11);
        var keyTwo = Key32(0x22);

        var options = new HashiCorpVaultKeyProviderOptions
        {
            TransitKeyName = TransitKey!,
            MountPoint = MountPoint,
            ActiveKeyId = 2,
        };
        options.WrappedKeys[1] = await WrapAsync(client, keyOne);
        options.WrappedKeys[2] = await WrapAsync(client, keyTwo);

        var decrypt = new LiveDecryptAdapter(client, TransitKey!, MountPoint);
        var provider = await HashiCorpVaultKeyProvider.CreateAsync(decrypt, options);

        Assert.Equal(2, provider.ActiveKeyId);
        Assert.True(keyOne.AsSpan().SequenceEqual(provider.TryGetKey(1)!.Value.Span));
        Assert.True(keyTwo.AsSpan().SequenceEqual(provider.TryGetKey(2)!.Value.Span));
    }

    [Fact]
    public async Task CreateAsync_rejects_wrong_length_plaintext_against_live_vault()
    {
        if (!IsConfigured)
        {
            return;
        }
        var client = BuildClient();
        var sixteen = new byte[16];
        Array.Fill(sixteen, (byte)0x33);

        var options = new HashiCorpVaultKeyProviderOptions
        {
            TransitKeyName = TransitKey!,
            MountPoint = MountPoint,
            ActiveKeyId = 1,
        };
        options.WrappedKeys[1] = await WrapAsync(client, sixteen);

        var decrypt = new LiveDecryptAdapter(client, TransitKey!, MountPoint);
        await Assert.ThrowsAsync<Moongazing.OrionVault.Exceptions.OrionVaultConfigurationException>(
            () => HashiCorpVaultKeyProvider.CreateAsync(decrypt, options));
    }

    private sealed class LiveDecryptAdapter : IVaultTransitDecryptClient
    {
        private readonly IVaultClient client;
        private readonly string transitKeyName;
        private readonly string mountPoint;

        public LiveDecryptAdapter(IVaultClient client, string transitKeyName, string mountPoint)
        {
            this.client = client;
            this.transitKeyName = transitKeyName;
            this.mountPoint = mountPoint;
        }

        public async Task<byte[]> DecryptAsync(string ciphertext, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var options = new DecryptRequestOptions
            {
                BatchedDecryptionItems = new List<DecryptionItem> { new() { CipherText = ciphertext } },
            };
            var response = await client.V1.Secrets.Transit.DecryptAsync(transitKeyName, options, mountPoint);
            return Convert.FromBase64String(response.Data.BatchedResults.First().Base64EncodedPlainText);
        }
    }
}
