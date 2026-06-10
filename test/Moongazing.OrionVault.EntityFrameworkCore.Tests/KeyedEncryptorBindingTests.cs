namespace Moongazing.OrionVault.EntityFrameworkCore.Tests;

using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore.Internal;
using Xunit;

public sealed class KeyedEncryptorBindingTests
{
    private sealed class StubKeyProvider : IKeyProvider
    {
        public StubKeyProvider(short activeKeyId, byte[] key)
        {
            ActiveKeyId = activeKeyId;
            Key = key;
        }
        public short ActiveKeyId { get; }
        public byte[] Key { get; }
        public ReadOnlyMemory<byte>? TryGetKey(short keyId)
            => keyId == ActiveKeyId ? Key : null;
    }

    private sealed class DummyDbContext : Microsoft.EntityFrameworkCore.DbContext { }

    private static byte[] NewKey() => System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);

    private static IServiceCollection BuildHostServices()
    {
        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
            o.ActiveKeyId = 1;
        })
            .AddNamedKeyProvider("primary", new StubKeyProvider(1, NewKey()))
            .AddNamedKeyProvider("audit", new StubKeyProvider(2, NewKey()))
            .UseEntityFrameworkCore<DummyDbContext>("primary")
            .UseEntityFrameworkCore<DummyDbContext>("audit");
        return services;
    }

    [Fact]
    public void Registers_keyed_IEncryptor_per_provider_name()
    {
        using var sp = BuildHostServices().BuildServiceProvider();
        var primary = sp.GetRequiredKeyedService<IEncryptor>("primary");
        var audit = sp.GetRequiredKeyedService<IEncryptor>("audit");
        Assert.NotNull(primary);
        Assert.NotNull(audit);
        Assert.NotSame(primary, audit);
    }

    [Fact]
    public void Registers_keyed_EncryptedValueConverterFactory_per_provider_name()
    {
        using var sp = BuildHostServices().BuildServiceProvider();
        var primary = sp.GetRequiredKeyedService<EncryptedValueConverterFactory>("primary");
        var audit = sp.GetRequiredKeyedService<EncryptedValueConverterFactory>("audit");
        Assert.NotSame(primary, audit);
    }

    [Fact]
    public void Registers_keyed_IEncryptionConfigurator_per_provider_name()
    {
        using var sp = BuildHostServices().BuildServiceProvider();
        var primary = sp.GetRequiredKeyedService<IEncryptionConfigurator>("primary");
        var audit = sp.GetRequiredKeyedService<IEncryptionConfigurator>("audit");
        Assert.NotSame(primary, audit);
    }

    [Fact]
    public void Keyed_IEncryptor_encrypts_with_the_named_providers_key_set()
    {
        var primaryKey = NewKey();
        var auditKey = NewKey();
        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
            o.ActiveKeyId = 1;
        })
            .AddNamedKeyProvider("primary", new StubKeyProvider(1, primaryKey))
            .AddNamedKeyProvider("audit", new StubKeyProvider(2, auditKey))
            .UseEntityFrameworkCore<DummyDbContext>("primary")
            .UseEntityFrameworkCore<DummyDbContext>("audit");

        using var sp = services.BuildServiceProvider();
        var primary = sp.GetRequiredKeyedService<IEncryptor>("primary");
        var audit = sp.GetRequiredKeyedService<IEncryptor>("audit");

        var cipherPrimary = primary.EncryptString("hello");
        var cipherAudit = audit.EncryptString("hello");

        // Round-trip on the matching encryptor succeeds.
        Assert.Equal("hello", primary.DecryptString(cipherPrimary));
        Assert.Equal("hello", audit.DecryptString(cipherAudit));

        // Cross-decrypt MUST fail because the key id in the cipher header maps to a key
        // the other provider does not have.
        Assert.ThrowsAny<Exception>(() => primary.DecryptString(cipherAudit));
        Assert.ThrowsAny<Exception>(() => audit.DecryptString(cipherPrimary));
    }

    [Fact]
    public void UseEntityFrameworkCore_keyed_overload_rejects_null_or_empty_providerName()
    {
        var services = new ServiceCollection();
        var builder = services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
            o.ActiveKeyId = 1;
        });
        Assert.Throws<ArgumentNullException>(() => builder.UseEntityFrameworkCore<DummyDbContext>(null!));
        Assert.Throws<ArgumentException>(() => builder.UseEntityFrameworkCore<DummyDbContext>(string.Empty));
    }

    [Fact]
    public void OrionVaultEncryptor_Create_builds_a_working_encryptor()
    {
        var keys = new StubKeyProvider(7, NewKey());
        var diag = new Moongazing.OrionVault.Diagnostics.OrionVaultDiagnostics();
        var encryptor = OrionVaultEncryptor.Create(keys, diag);

        var cipher = encryptor.EncryptString("ping");
        Assert.Equal("ping", encryptor.DecryptString(cipher));
    }
}
