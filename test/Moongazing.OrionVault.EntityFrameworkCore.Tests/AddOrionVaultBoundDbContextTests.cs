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

public sealed class AddOrionVaultBoundDbContextTests
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

    private const string BaseKey64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    [Fact]
    public async Task AddOrionVaultBoundDbContext_round_trips_encrypted_column_through_the_keyed_provider()
    {
        await using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();
        var primaryKey = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);

        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, BaseKey64));
            o.ActiveKeyId = 1;
        })
            .AddNamedKeyProvider("primary", new StubKeyProvider(activeKeyId: 11, primaryKey))
            .AddOrionVaultBoundDbContext<PrimaryDb>(
                "primary",
                (sp, opt) => opt.UseSqlite(connection));

        await using var sp = services.BuildServiceProvider();
        await using var scope = sp.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<PrimaryDb>();
        await db.Database.EnsureCreatedAsync();

        db.Items.Add(new PrimaryEntity { Secret = "round-trip" });
        await db.SaveChangesAsync();

        // Resolve a FRESH DbContext from a new scope to force a SELECT.
        await using var readScope = sp.CreateAsyncScope();
        var readDb = readScope.ServiceProvider.GetRequiredService<PrimaryDb>();
        var row = await readDb.Items.SingleAsync();
        Assert.Equal("round-trip", row.Secret);
    }

    [Fact]
    public void AddOrionVaultBoundDbContext_rejects_null_or_empty_providerName()
    {
        var services = new ServiceCollection();
        var builder = services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, BaseKey64));
            o.ActiveKeyId = 1;
        });

        Assert.Throws<ArgumentNullException>(() =>
            builder.AddOrionVaultBoundDbContext<PrimaryDb>(null!, (_, _) => { }));
        Assert.Throws<ArgumentException>(() =>
            builder.AddOrionVaultBoundDbContext<PrimaryDb>(string.Empty, (_, _) => { }));
        Assert.Throws<ArgumentNullException>(() =>
            builder.AddOrionVaultBoundDbContext<PrimaryDb>("primary", null!));
    }

    [Fact]
    public void AddOrionVaultBoundDbContext_registers_KeyedOrionVaultBinding_singleton()
    {
        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, BaseKey64));
            o.ActiveKeyId = 1;
        })
            .AddNamedKeyProvider("primary", new StubKeyProvider(activeKeyId: 1,
                System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)))
            .AddOrionVaultBoundDbContext<PrimaryDb>(
                "primary",
                (sp, opt) => opt.UseSqlite("DataSource=:memory:"));

        using var sp = services.BuildServiceProvider();
        var binding = sp.GetRequiredService<KeyedOrionVaultBinding<PrimaryDb>>();
        Assert.Equal("primary", binding.ProviderName);
    }
}
