namespace Moongazing.OrionVault.GcpKms.IntegrationTests;

using Google.Cloud.Kms.V1;
using Google.Protobuf;
using Moongazing.OrionVault.GcpKms;
using Xunit;

/// <summary>
/// Live Google Cloud KMS integration tests. Skipped locally unless the consumer sets the required
/// environment variables:
/// <list type="bullet">
///   <item><description><c>ORIONVAULT_GCP_CRYPTO_KEY</c> - a full Cloud KMS crypto-key resource name,
///   e.g. <c>projects/p/locations/global/keyRings/r/cryptoKeys/k</c>.</description></item>
/// </list>
/// Credentials flow through Application Default Credentials (ADC), so any of the standard
/// discovery entries work (workload identity, <c>gcloud auth application-default login</c>, a
/// service-account key file via <c>GOOGLE_APPLICATION_CREDENTIALS</c>).
/// </summary>
/// <remarks>
/// Cloud KMS has no widely-available local emulator in this toolchain (LocalStack covers AWS, not
/// GCP). These tests are therefore CONDITIONAL on consumer-supplied credentials, mirroring the
/// Azure Key Vault live suite; the mock-seam unit tests provide the on-CI coverage for the same
/// provider contract.
/// </remarks>
[Trait("Category", "Integration")]
public sealed class GcpKmsKeyProviderLiveTests
{
    private static readonly string? CryptoKey = Environment.GetEnvironmentVariable("ORIONVAULT_GCP_CRYPTO_KEY");
    public static bool IsConfigured => !string.IsNullOrEmpty(CryptoKey);

    private static byte[] Key32(byte fill)
    {
        var bytes = new byte[32];
        Array.Fill(bytes, fill);
        return bytes;
    }

    private static async Task<string> WrapAsync(KeyManagementServiceClient kms, byte[] plaintext)
    {
        var response = await kms.EncryptAsync(CryptoKeyName.Parse(CryptoKey!), ByteString.CopyFrom(plaintext));
        return Convert.ToBase64String(response.Ciphertext.ToByteArray());
    }

    [Fact]
    public async Task CreateAsync_unwraps_two_keys_against_live_kms()
    {
        if (!IsConfigured)
        {
            return; // Vacuous pass when env vars are absent; the real assertion only runs live.
        }
        var kms = await KeyManagementServiceClient.CreateAsync();
        var keyOne = Key32(0x11);
        var keyTwo = Key32(0x22);

        var options = new GcpKmsKeyProviderOptions { CryptoKeyName = CryptoKey!, ActiveKeyId = 2 };
        options.WrappedKeys[1] = await WrapAsync(kms, keyOne);
        options.WrappedKeys[2] = await WrapAsync(kms, keyTwo);

        var decrypt = new LiveDecryptAdapter(kms, CryptoKey!);
        var provider = await GcpKmsKeyProvider.CreateAsync(decrypt, options);

        Assert.Equal(2, provider.ActiveKeyId);
        Assert.True(keyOne.AsSpan().SequenceEqual(provider.TryGetKey(1)!.Value.Span));
        Assert.True(keyTwo.AsSpan().SequenceEqual(provider.TryGetKey(2)!.Value.Span));
    }

    [Fact]
    public async Task CreateAsync_rejects_wrong_length_plaintext_against_live_kms()
    {
        if (!IsConfigured)
        {
            return;
        }
        var kms = await KeyManagementServiceClient.CreateAsync();
        var sixteen = new byte[16];
        Array.Fill(sixteen, (byte)0x33);

        var options = new GcpKmsKeyProviderOptions { CryptoKeyName = CryptoKey!, ActiveKeyId = 1 };
        options.WrappedKeys[1] = await WrapAsync(kms, sixteen);

        var decrypt = new LiveDecryptAdapter(kms, CryptoKey!);
        await Assert.ThrowsAsync<Moongazing.OrionVault.Exceptions.OrionVaultConfigurationException>(
            () => GcpKmsKeyProvider.CreateAsync(decrypt, options));
    }

    private sealed class LiveDecryptAdapter : IGcpKmsDecryptClient
    {
        private readonly KeyManagementServiceClient client;
        private readonly CryptoKeyName cryptoKeyName;

        public LiveDecryptAdapter(KeyManagementServiceClient client, string cryptoKeyName)
        {
            this.client = client;
            this.cryptoKeyName = CryptoKeyName.Parse(cryptoKeyName);
        }

        public async Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken cancellationToken)
        {
            var response = await client.DecryptAsync(cryptoKeyName, ByteString.CopyFrom(ciphertext), cancellationToken);
            return response.Plaintext.ToByteArray();
        }
    }
}
