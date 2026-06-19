namespace Moongazing.OrionVault.Tests.BlindIndex;

using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.BlindIndex;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Exceptions;
using Xunit;

public class BlindIndexConfigurationTests
{
    private const string EncKeyB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    private const string IndexKeyB64 = "ERERERERERERERERERERERERERERERERERERERERERE=";

    [Fact]
    public void Builder_rejects_duplicate_version()
    {
        var b = new BlindIndexKeysBuilder().Add(1, IndexKeyB64);

        var act = () => b.Add(1, IndexKeyB64);

        act.Should().Throw<OrionVaultConfigurationException>().WithMessage("*Duplicate*");
    }

    [Fact]
    public void Builder_rejects_invalid_base64()
    {
        var act = () => new BlindIndexKeysBuilder().Add(1, "not base64 %%%");

        act.Should().Throw<OrionVaultConfigurationException>().WithMessage("*base64*");
    }

    [Fact]
    public void Builder_rejects_key_shorter_than_16_bytes()
    {
        var act = () => new BlindIndexKeysBuilder().Add(1, new byte[8]);

        act.Should().Throw<OrionVaultConfigurationException>().WithMessage("*expected at least*");
    }

    [Fact]
    public void Builder_accepts_raw_byte_key_and_copies_it()
    {
        var raw = new byte[32];
        Array.Fill(raw, (byte)5);
        var provider = new HmacBlindIndexProvider(
            new BlindIndexKeysBuilderAccessor(new BlindIndexKeysBuilder().Add(1, raw)).Keys, 1);

        // Mutating the source after building must not change index output.
        var before = provider.Compute("x").Bytes;
        Array.Fill(raw, (byte)9);
        provider.Compute("x").Bytes.Should().Equal(before);
    }

    [Fact]
    public void AddOrionVault_throws_when_active_blind_index_version_not_registered()
    {
        var act = () => new ServiceCollection().AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, EncKeyB64));
            o.ActiveKeyId = 1;
            o.UseBlindIndex(b => b.Add(1, IndexKeyB64));
            o.ActiveBlindIndexVersion = 7;
        });

        act.Should().Throw<OrionVaultConfigurationException>().WithMessage("*7*");
    }

    [Fact]
    public void AddOrionVault_throws_when_UseBlindIndex_adds_no_keys()
    {
        var act = () => new ServiceCollection().AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, EncKeyB64));
            o.ActiveKeyId = 1;
            o.UseBlindIndex(_ => { });
        });

        act.Should().Throw<OrionVaultConfigurationException>().WithMessage("*no index key*");
    }

    // Test helper that surfaces the internal Build() result of a builder via InternalsVisibleTo.
    private sealed class BlindIndexKeysBuilderAccessor
    {
        public BlindIndexKeysBuilderAccessor(BlindIndexKeysBuilder builder) => Keys = builder.Build();

        public IReadOnlyDictionary<short, byte[]> Keys { get; }
    }
}
