namespace Moongazing.OrionVault.Tests.BlindIndex;

using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Xunit;

/// <summary>
/// The defining property of searchable encryption in this library: for the same plaintext the
/// blind index is deterministic (equal) so it is searchable, while the stored ciphertext is
/// randomized (unequal) so it leaks nothing beyond what the index deliberately exposes.
/// </summary>
public class BlindIndexVersusCiphertextTests
{
    private const string EncryptionKeyB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    // A DIFFERENT secret for the index than the encryption key.
    private const string IndexKeyB64 = "ERERERERERERERERERERERERERERERERERERERERERE=";

    private static ServiceProvider BuildProvider()
        => new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(1, EncryptionKeyB64));
                o.ActiveKeyId = 1;
                o.UseBlindIndex(b => b.Add(1, IndexKeyB64));
                o.ActiveBlindIndexVersion = 1;
            })
            .Services
            .BuildServiceProvider();

    [Fact]
    public void Same_plaintext_yields_equal_blind_index_but_differing_ciphertext()
    {
        using var sp = BuildProvider();
        var encryptor = sp.GetRequiredService<IEncryptor>();
        var index = sp.GetRequiredService<IBlindIndexProvider>();

        const string value = "ali@example.com";

        var cipher1 = encryptor.EncryptString(value);
        var cipher2 = encryptor.EncryptString(value);
        var blind1 = index.Compute(value);
        var blind2 = index.Compute(value);

        // Randomized encryption: two ciphertexts of the same value differ (different nonce).
        cipher1.Should().NotEqual(cipher2);
        // Deterministic blind index: two indexes of the same value are equal (searchable).
        blind1.Bytes.Should().Equal(blind2.Bytes);
        // And both ciphertexts still decrypt back to the original.
        encryptor.DecryptString(cipher1).Should().Be(value);
        encryptor.DecryptString(cipher2).Should().Be(value);
    }

    [Fact]
    public void Blind_index_is_independent_of_the_encryption_key()
    {
        using var sp = BuildProvider();
        var encryptor = sp.GetRequiredService<IEncryptor>();
        var index = sp.GetRequiredService<IBlindIndexProvider>();

        // The index must not equal the ciphertext body, and the index of an unrelated value must
        // differ - sanity that the two subsystems are not accidentally the same transform.
        var blind = index.Compute("ali@example.com").Bytes;
        var cipher = encryptor.EncryptString("ali@example.com");

        blind.Should().NotEqual(cipher);
        index.Compute("veli@example.com").Bytes.Should().NotEqual(blind);
    }

    [Fact]
    public void BlindIndexProvider_is_a_singleton()
    {
        using var sp = BuildProvider();

        var first = sp.GetRequiredService<IBlindIndexProvider>();
        var second = sp.GetRequiredService<IBlindIndexProvider>();

        first.Should().BeSameAs(second);
    }

    [Fact]
    public void BlindIndexProvider_is_not_registered_when_not_configured()
    {
        using var sp = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(1, EncryptionKeyB64));
                o.ActiveKeyId = 1;
            })
            .Services
            .BuildServiceProvider();

        sp.GetService<IBlindIndexProvider>().Should().BeNull();
    }
}
