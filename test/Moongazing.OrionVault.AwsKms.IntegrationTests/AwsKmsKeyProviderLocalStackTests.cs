namespace Moongazing.OrionVault.AwsKms.IntegrationTests;

using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using Moongazing.OrionVault.AwsKms;
using Testcontainers.LocalStack;
using Xunit;

/// <summary>
/// End-to-end integration tests for <see cref="AwsKmsKeyProvider"/> against a
/// LocalStack-hosted KMS emulator. Spins up the container per fixture, generates two CMKs,
/// wraps 32-byte plaintext keys under them, and exercises the production
/// <see cref="AwsKmsKeyProvider.CreateAsync"/> path so unwrap behaviour, CMK pinning,
/// parallel decrypt, and validation errors are covered against a real AWS API surface (not
/// the unit-test mocks).
/// </summary>
[Trait("Category", "Integration")]
public sealed class AwsKmsKeyProviderLocalStackTests : IAsyncLifetime
{
    private readonly LocalStackContainer container = new LocalStackBuilder()
        .WithImage("localstack/localstack:3.7.0")
        .Build();

    private AmazonKeyManagementServiceClient kms = default!;
    private string cmkId = default!;

    // A second, independent CMK standing in for "a key the attacker controls but the host
    // principal can nonetheless call kms:Decrypt on" - the cross-account / Resource:"*" shape.
    private string foreignCmkId = default!;

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

        cmkId = await CreateCmkAsync("OrionVault integration test CMK");
        foreignCmkId = await CreateCmkAsync("OrionVault integration test foreign CMK");
    }

    public async Task DisposeAsync()
    {
        kms?.Dispose();
        await container.DisposeAsync();
    }

    private async Task<string> CreateCmkAsync(string description)
    {
        var cmk = await kms.CreateKeyAsync(new CreateKeyRequest
        {
            Description = description,
            KeyUsage = KeyUsageType.ENCRYPT_DECRYPT,
        });
        return cmk.KeyMetadata.KeyId;
    }

    private Task<string> WrapAsync(byte[] plaintext) => WrapUnderAsync(cmkId, plaintext);

    private async Task<string> WrapUnderAsync(string keyId, byte[] plaintext)
    {
        using var ms = new MemoryStream(plaintext);
        var encrypted = await kms.EncryptAsync(new EncryptRequest
        {
            KeyId = keyId,
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

        var options = new AwsKmsKeyProviderOptions { KeyId = cmkId, ActiveKeyId = 2 };
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
        var options = new AwsKmsKeyProviderOptions { KeyId = cmkId, ActiveKeyId = 0 };
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
        var options = new AwsKmsKeyProviderOptions { KeyId = cmkId, ActiveKeyId = 1 };
        options.WrappedKeys[1] = await WrapAsync(sixteen);

        await Assert.ThrowsAsync<Moongazing.OrionVault.Exceptions.OrionVaultConfigurationException>(
            () => AwsKmsKeyProvider.CreateAsync(kms, options));
    }

    [Fact]
    public async Task CreateAsync_refuses_a_blob_wrapped_under_a_CMK_other_than_the_configured_one()
    {
        // The substitution this pins down: someone who can influence WrappedKeys (config store,
        // environment variable, appsettings.json in the image, compromised deploy pipeline)
        // supplies a 32-byte data key they wrapped under a CMK *they* control, which the host
        // principal happens to hold kms:Decrypt on. With no KeyId on the DecryptRequest, KMS
        // resolves the key from the blob's own metadata and decrypts it happily - the attacker's
        // key silently becomes OrionVault's active data key, and the 32-byte length check (the
        // provider's only other validation) passes. Pinning the CMK is what stops it.
        var attackerKey = Key32(0x44);
        var options = new AwsKmsKeyProviderOptions { KeyId = cmkId, ActiveKeyId = 1 };
        options.WrappedKeys[1] = await WrapUnderAsync(foreignCmkId, attackerKey);

        var ex = await Assert.ThrowsAnyAsync<AmazonKeyManagementServiceException>(
            () => AwsKmsKeyProvider.CreateAsync(kms, options));

        // Whatever KMS calls it, the point is that no provider came back holding the substituted
        // key. Guard against a future refactor turning the throw into a silent fallback.
        Assert.NotNull(ex);
    }

    [Fact]
    public async Task CreateAsync_accepts_the_same_blob_when_configured_for_the_CMK_it_was_wrapped_under()
    {
        // Positive control for the test above: the blob itself is perfectly valid. It is the
        // mismatch against the configured CMK - not a malformed ciphertext - that gets it refused.
        var key = Key32(0x44);
        var blob = await WrapUnderAsync(foreignCmkId, key);

        var options = new AwsKmsKeyProviderOptions { KeyId = foreignCmkId, ActiveKeyId = 1 };
        options.WrappedKeys[1] = blob;

        var provider = await AwsKmsKeyProvider.CreateAsync(kms, options);

        Assert.True(key.AsSpan().SequenceEqual(provider.TryGetKey(1)!.Value.Span));
    }

    [Fact]
    public async Task CreateAsync_fails_fast_when_no_CMK_is_configured()
    {
        // A deployment that forgot to pin its CMK must not fall back to "let KMS pick"; it must
        // stop at startup with the option name in the message.
        var options = new AwsKmsKeyProviderOptions { ActiveKeyId = 1 };
        options.WrappedKeys[1] = await WrapAsync(Key32(0x11));

        var ex = await Assert.ThrowsAsync<Moongazing.OrionVault.Exceptions.OrionVaultConfigurationException>(
            () => AwsKmsKeyProvider.CreateAsync(kms, options));
        Assert.Contains("KeyId", ex.Message, StringComparison.Ordinal);
    }
}
