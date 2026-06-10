namespace Moongazing.OrionVault.EntityFrameworkCore.Tests;

using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;
using Xunit;

public sealed class KeyedOrionVaultModelCustomizerTests
{
    public sealed class PrimaryEntity
    {
        public int Id { get; set; }
        [Moongazing.OrionVault.EntityFrameworkCore.Encrypted]
        public string Secret { get; set; } = string.Empty;
    }

    public sealed class PrimaryDb : DbContext
    {
        public PrimaryDb(DbContextOptions<PrimaryDb> options) : base(options) { }
        public DbSet<PrimaryEntity> Items => Set<PrimaryEntity>();
    }

    public sealed class AuditEntity
    {
        public int Id { get; set; }
        [Moongazing.OrionVault.EntityFrameworkCore.Encrypted]
        public string Diff { get; set; } = string.Empty;
    }

    public sealed class AuditDb : DbContext
    {
        public AuditDb(DbContextOptions<AuditDb> options) : base(options) { }
        public DbSet<AuditEntity> Events => Set<AuditEntity>();
    }

    private const string BaseKey64 =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    [Fact]
    public void KeyedOrionVaultBinding_rejects_null_or_empty_providerName()
    {
        Assert.Throws<ArgumentNullException>(() => new KeyedOrionVaultBinding<PrimaryDb>(null!));
        Assert.Throws<ArgumentException>(() => new KeyedOrionVaultBinding<PrimaryDb>(string.Empty));
    }

    [Fact]
    public async Task Two_DbContexts_route_to_distinct_keyed_configurators_via_bindings()
    {
        await using var primaryConn = new SqliteConnection("DataSource=:memory:");
        await using var auditConn = new SqliteConnection("DataSource=:memory:");
        await primaryConn.OpenAsync();
        await auditConn.OpenAsync();

        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, BaseKey64));
            o.ActiveKeyId = 1;
        })
            .AddNamedKeyProvider("primary", BuildStubProvider(activeKeyId: 11))
            .AddNamedKeyProvider("audit", BuildStubProvider(activeKeyId: 22))
            .UseEntityFrameworkCore<PrimaryDb>("primary")
            .UseEntityFrameworkCore<AuditDb>("audit");

        services.AddSingleton(new KeyedOrionVaultBinding<PrimaryDb>("primary"));
        services.AddSingleton(new KeyedOrionVaultBinding<AuditDb>("audit"));

        services.AddDbContext<PrimaryDb>((sp, opt) =>
        {
            opt.UseSqlite(primaryConn);
            opt.UseApplicationServiceProvider(sp);
            opt.ReplaceService<Microsoft.EntityFrameworkCore.Infrastructure.IModelCustomizer,
                KeyedOrionVaultModelCustomizer<PrimaryDb>>();
        });
        services.AddDbContext<AuditDb>((sp, opt) =>
        {
            opt.UseSqlite(auditConn);
            opt.UseApplicationServiceProvider(sp);
            opt.ReplaceService<Microsoft.EntityFrameworkCore.Infrastructure.IModelCustomizer,
                KeyedOrionVaultModelCustomizer<AuditDb>>();
        });

        await using var sp = services.BuildServiceProvider();
        await using var pscope = sp.CreateAsyncScope();
        var pdb = pscope.ServiceProvider.GetRequiredService<PrimaryDb>();
        await pdb.Database.EnsureCreatedAsync();
        pdb.Items.Add(new PrimaryEntity { Secret = "primary-secret" });
        await pdb.SaveChangesAsync();

        await using var ascope = sp.CreateAsyncScope();
        var adb = ascope.ServiceProvider.GetRequiredService<AuditDb>();
        await adb.Database.EnsureCreatedAsync();
        adb.Events.Add(new AuditEntity { Diff = "audit-secret" });
        await adb.SaveChangesAsync();

        // Round-trip each context independently. The KEYED encryptors round-trip with
        // their own key sets, so cross-decrypt would fail if the model customizer routed
        // through the wrong provider.
        var primaryRow = await pdb.Items.FirstAsync();
        Assert.Equal("primary-secret", primaryRow.Secret);
        var auditRow = await adb.Events.FirstAsync();
        Assert.Equal("audit-secret", auditRow.Diff);
    }

    [Fact]
    public void Customizer_resolves_binding_and_configurator_through_application_SP()
    {
        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, BaseKey64));
            o.ActiveKeyId = 1;
        })
            .AddNamedKeyProvider("primary", BuildStubProvider(activeKeyId: 11))
            .UseEntityFrameworkCore<PrimaryDb>("primary");
        services.AddSingleton(new KeyedOrionVaultBinding<PrimaryDb>("primary"));

        using var sp = services.BuildServiceProvider();
        var binding = sp.GetRequiredService<KeyedOrionVaultBinding<PrimaryDb>>();
        Assert.Equal("primary", binding.ProviderName);
        var configurator = sp.GetRequiredKeyedService<IEncryptionConfigurator>(binding.ProviderName);
        Assert.NotNull(configurator);
    }

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

    private static IKeyProvider BuildStubProvider(short activeKeyId)
        => new StubKeyProvider(activeKeyId, System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
}
