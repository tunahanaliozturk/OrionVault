namespace Moongazing.OrionVault.Testing.Tests;

using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Testing;
using Moongazing.OrionVault.Testing.DependencyInjection;
using Xunit;

public class TestingPackageTests
{
    [Fact]
    public void TestKeyProvider_Default_returns_active_key_id_1_and_zero_key()
    {
        var sut = TestKeyProvider.Default;
        sut.ActiveKeyId.Should().Be(1);
        sut.TryGetKey(1).Should().NotBeNull();
        sut.TryGetKey(1)!.Value.Length.Should().Be(32);
        sut.TryGetKey(99).Should().BeNull();
    }

    [Fact]
    public void TestKeyProvider_Add_registers_an_extra_key()
    {
        var sut = new TestKeyProvider(activeKeyId: 1);
        var k2 = new byte[32]; k2[0] = 0xFF;
        sut.Add(2, k2);

        sut.TryGetKey(2)!.Value.Span[0].Should().Be(0xFF);
    }

    [Fact]
    public void PlaintextEncryptor_round_trips_string_with_30_byte_header()
    {
        var sut = new PlaintextEncryptor();
        var ct = sut.EncryptString("hello");
        ct.Length.Should().Be(30 + 5);
        sut.DecryptString(ct).Should().Be("hello");
    }

    [Fact]
    public void EncryptionAssertions_IsEncryptedWithKey_passes_for_correct_key()
    {
        var sp = new ServiceCollection().AddOrionVaultForTesting().Services.BuildServiceProvider();
        var enc = sp.GetRequiredService<IEncryptor>();
        var ct = enc.EncryptString("x");

        EncryptionAssertions.IsEncrypted(ct);
        EncryptionAssertions.ReadKeyId(ct).Should().Be(1);
        EncryptionAssertions.IsEncryptedWithKey(ct, expectedKeyId: 1);
    }

    [Fact]
    public void AddOrionVaultForTesting_wires_TestKeyProvider_and_round_trips_a_value()
    {
        var sp = new ServiceCollection()
            .AddOrionVaultForTesting()
            .Services
            .BuildServiceProvider();
        sp.GetRequiredService<IKeyProvider>().Should().BeOfType<TestKeyProvider>();
        var enc = sp.GetRequiredService<IEncryptor>();
        enc.DecryptString(enc.EncryptString("x")).Should().Be("x");
    }
}
