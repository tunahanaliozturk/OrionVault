namespace Moongazing.OrionVault.AwsKms.IntegrationTests;

using Amazon;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using Moongazing.OrionVault.AwsKms;
using Testcontainers.LocalStack;
using Xunit;

/// <summary>
/// End-to-end integration tests for <see cref="AwsKmsKeyProvider"/> against a
/// LocalStack-hosted KMS emulator. Spins up the container per fixture, generates a CMK,
/// wraps two 32-byte plaintext keys, and exercises the production
/// <see cref="AwsKmsKeyProvider.CreateAsync"/> path so unwrap behaviour, parallel decrypt,
/// and validation errors are covered against a real AWS API surface (not the unit-test
/// mocks).
/// </summary>
[Trait("Category", "Integration")]
public sealed class AwsKmsKeyProviderLocalStackTests : IAsyncLifetime
{
    private readonly LocalStackContainer container = new LocalStackBuilder()
        .WithImage("localstack/localstack:3.7.0")
        .Build();

    private AmazonKeyManagementServiceClient kms = default!;
    private string cmkId = default!;

    public async Task InitializeAsync()
    {
        await container.StartAsync();
        var config = new AmazonKeyManagementServiceConfig
        {
            ServiceURL = container.GetConnectionString(),
            AuthenticationRegion = "us-east-1",
            UseHttp = true,
        };
        kms = new AmazonKeyManagementServiceClient(
            new BasicAWSCredentials("test", "test"),
            config);

        var cmk = await kms.CreateKeyAsync(new CreateKeyRequest
        {
            Description = "OrionVault integration test CMK",
            KeyUsage = KeyUsageType.ENCRYPT_DECRYPT,
        });
        cmkId = cmk.KeyMetadata.KeyId;
    }

    public async Task DisposeAsync()
    {
        kms?.Dispose();
        await container.DisposeAsync();
    }

    private async Task<string> WrapAsync(byte[] plaintext)
    {
        using var ms = new MemoryStream(plaintext);
        var encrypted = await kms.EncryptAsync(new EncryptRequest
        {
            KeyId = cmkId,
            Plaintext = ms,
        });
        return Convert.ToBase64String(encrypted.CiphertextBlob.ToArray());
    }

    private static byte[] Key32(byte fill)
    {
        var bytes = new byte[32];
        Array.Fill(bytes, fill);
        return bytes;
    }

    [Fact]
    public async Task CreateAsync_unwraps_two_keys_against_LocalStack_and_active_id_is_resolvable()
    {
        var keyOne = Key32(0x11);
        var keyTwo = Key32(0x22);

        var options = new AwsKmsKeyProviderOptions { ActiveKeyId = 2 };
        options.WrappedKeys[1] = await WrapAsync(keyOne);
        options.WrappedKeys[2] = await WrapAsync(keyTwo);

        var provider = await AwsKmsKeyProvider.CreateAsync(kms, options);

        Assert.Equal(2, provider.ActiveKeyId);
        Assert.True(keyOne.AsSpan().SequenceEqual(provider.TryGetKey(1)!.Value.Span));
        Assert.True(keyTwo.AsSpan().SequenceEqual(provider.TryGetKey(2)!.Value.Span));
        Assert.Null(provider.TryGetKey(99));
    }

    [Fact]
    public async Task CreateAsync_runs_decrypts_in_parallel_against_LocalStack()
    {
        // 8 keys; wall-clock should not be 8x a single-key latency because CreateAsync
        // dispatches the decrypts concurrently. We don't assert latency directly (LocalStack
        // is fast enough that a sequential and parallel run differ by milliseconds), but the
        // success path with N entries verifies the WhenAll fan-out at least completes
        // without serialisation deadlocks.
        var options = new AwsKmsKeyProviderOptions { ActiveKeyId = 0 };
        for (short i = 0; i < 8; i++)
        {
            options.WrappedKeys[i] = await WrapAsync(Key32((byte)(0x10 + i)));
        }

        var provider = await AwsKmsKeyProvider.CreateAsync(kms, options);

        for (short i = 0; i < 8; i++)
        {
            var expected = Key32((byte)(0x10 + i));
            Assert.True(expected.AsSpan().SequenceEqual(provider.TryGetKey(i)!.Value.Span));
        }
    }

    [Fact]
    public async Task CreateAsync_rejects_wrong_length_plaintext_from_LocalStack_unwrap()
    {
        // Wrap a 16-byte plaintext (deliberately wrong). LocalStack happily decrypts to 16
        // bytes; the provider's post-unwrap validation must reject it as != 32 bytes.
        var sixteen = new byte[16];
        Array.Fill(sixteen, (byte)0x33);
        var options = new AwsKmsKeyProviderOptions { ActiveKeyId = 1 };
        options.WrappedKeys[1] = await WrapAsync(sixteen);

        await Assert.ThrowsAsync<Moongazing.OrionVault.Exceptions.OrionVaultConfigurationException>(
            () => AwsKmsKeyProvider.CreateAsync(kms, options));
    }
}
