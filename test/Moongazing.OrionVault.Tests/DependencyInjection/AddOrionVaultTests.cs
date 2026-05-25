namespace Moongazing.OrionVault.Tests.DependencyInjection;

using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Exceptions;
using Xunit;

public class AddOrionVaultTests
{
    private const string Key32B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    [Fact]
    public void AddOrionVault_registers_singletons_and_round_trips_a_value()
    {
        var sp = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(keyId: 1, base64Key: Key32B64));
                o.ActiveKeyId = 1;
            })
            .Services
            .BuildServiceProvider();

        var encryptor = sp.GetRequiredService<IEncryptor>();
        var keys = sp.GetRequiredService<IKeyProvider>();

        keys.ActiveKeyId.Should().Be(1);
        var ct = encryptor.EncryptString("hello");
        encryptor.DecryptString(ct).Should().Be("hello");
    }

    [Fact]
    public void AddOrionVault_throws_if_ActiveKeyId_not_registered()
    {
        var act = () => new ServiceCollection().AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(keyId: 1, base64Key: Key32B64));
            o.ActiveKeyId = 99;
        });

        act.Should().Throw<OrionVaultConfigurationException>()
            .WithMessage("*99*");
    }

    [Fact]
    public void AddOrionVault_throws_if_no_keys_registered()
    {
        var act = () => new ServiceCollection().AddOrionVault(o =>
        {
            o.ActiveKeyId = 1;
        });

        act.Should().Throw<OrionVaultConfigurationException>()
            .WithMessage("*at least one key*");
    }

    [Fact]
    public void StaticKeys_Add_throws_on_duplicate_key_id()
    {
        var act = () => new ServiceCollection().AddOrionVault(o =>
        {
            o.UseStaticKeys(k =>
            {
                k.Add(keyId: 1, base64Key: Key32B64);
                k.Add(keyId: 1, base64Key: Key32B64);
            });
            o.ActiveKeyId = 1;
        });

        act.Should().Throw<OrionVaultConfigurationException>()
            .WithMessage("*duplicate*1*");
    }

    [Fact]
    public void StaticKeys_Add_throws_on_non_32_byte_key()
    {
        const string shortKey = "AAAAAAAAAA==";
        var act = () => new ServiceCollection().AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(keyId: 1, base64Key: shortKey));
            o.ActiveKeyId = 1;
        });

        act.Should().Throw<OrionVaultConfigurationException>()
            .WithMessage("*32 bytes*");
    }
}
