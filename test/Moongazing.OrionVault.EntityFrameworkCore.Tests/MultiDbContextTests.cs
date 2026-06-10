namespace Moongazing.OrionVault.EntityFrameworkCore.Tests;

using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;
using Xunit;

public sealed class MultiDbContextTests : IDisposable
{
    private const string Key32B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    private readonly SqliteConnection primaryConn;
    private readonly SqliteConnection auditConn;

    public class PrimaryRow
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = null!;
        [Encrypted] public string Email { get; set; } = null!;
    }

    public class AuditRow
    {
        public Guid Id { get; set; }
        public string Action { get; set; } = null!;
        [Encrypted] public string ActorEmail { get; set; } = null!;
    }

    public class PrimaryCtx : DbContext
    {
        public PrimaryCtx(DbContextOptions<PrimaryCtx> opt) : base(opt) { }
        public DbSet<PrimaryRow> Rows => Set<PrimaryRow>();
    }

    public class AuditCtx : DbContext
    {
        public AuditCtx(DbContextOptions<AuditCtx> opt) : base(opt) { }
        public DbSet<AuditRow> Rows => Set<AuditRow>();
    }

    public MultiDbContextTests()
    {
        primaryConn = new SqliteConnection("Filename=:memory:");
        primaryConn.Open();
        auditConn = new SqliteConnection("Filename=:memory:");
        auditConn.Open();
    }

    public void Dispose()
    {
        primaryConn.Dispose();
        auditConn.Dispose();
    }

    [Fact]
    public async Task UseEntityFrameworkCore_can_register_two_DbContext_types_sharing_one_encryptor()
    {
        await using var sp = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(1, Key32B64));
                o.ActiveKeyId = 1;
            })
            .UseEntityFrameworkCore<PrimaryCtx>()
            .UseEntityFrameworkCore<AuditCtx>()
            .Services
            .AddDbContext<PrimaryCtx>((s, o) => o.UseSqlite(primaryConn).UseOrionVault(s))
            .AddDbContext<AuditCtx>((s, o) => o.UseSqlite(auditConn).UseOrionVault(s))
            .BuildServiceProvider();

        // Both contexts must accept encrypted writes and round-trip the plaintext.
        using (var scope = sp.CreateScope())
        {
            var primary = scope.ServiceProvider.GetRequiredService<PrimaryCtx>();
            var audit = scope.ServiceProvider.GetRequiredService<AuditCtx>();
            await primary.Database.EnsureCreatedAsync();
            await audit.Database.EnsureCreatedAsync();

            primary.Rows.Add(new PrimaryRow { Id = Guid.NewGuid(), Name = "Alice", Email = "alice@example.com" });
            audit.Rows.Add(new AuditRow { Id = Guid.NewGuid(), Action = "login", ActorEmail = "alice@example.com" });
            await primary.SaveChangesAsync();
            await audit.SaveChangesAsync();
        }

        using (var scope = sp.CreateScope())
        {
            var primary = scope.ServiceProvider.GetRequiredService<PrimaryCtx>();
            var audit = scope.ServiceProvider.GetRequiredService<AuditCtx>();
            var pRow = await primary.Rows.SingleAsync();
            var aRow = await audit.Rows.SingleAsync();

            pRow.Email.Should().Be("alice@example.com");
            aRow.ActorEmail.Should().Be("alice@example.com");
        }
    }

    [Fact]
    public async Task Stored_ciphertext_differs_across_two_DbContext_writes_due_to_per_call_nonce()
    {
        await using var sp = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(1, Key32B64));
                o.ActiveKeyId = 1;
            })
            .UseEntityFrameworkCore<PrimaryCtx>()
            .UseEntityFrameworkCore<AuditCtx>()
            .Services
            .AddDbContext<PrimaryCtx>((s, o) => o.UseSqlite(primaryConn).UseOrionVault(s))
            .AddDbContext<AuditCtx>((s, o) => o.UseSqlite(auditConn).UseOrionVault(s))
            .BuildServiceProvider();

        using var scope = sp.CreateScope();
        var primary = scope.ServiceProvider.GetRequiredService<PrimaryCtx>();
        var audit = scope.ServiceProvider.GetRequiredService<AuditCtx>();
        await primary.Database.EnsureCreatedAsync();
        await audit.Database.EnsureCreatedAsync();

        primary.Rows.Add(new PrimaryRow { Id = Guid.NewGuid(), Name = "Bob", Email = "shared@example.com" });
        audit.Rows.Add(new AuditRow { Id = Guid.NewGuid(), Action = "login", ActorEmail = "shared@example.com" });
        await primary.SaveChangesAsync();
        await audit.SaveChangesAsync();

        // Read raw ciphertext from each connection; they must be different even though the
        // plaintext, key, and encryptor are all the same (AES-GCM uses a fresh nonce per call).
        using var pCmd = primaryConn.CreateCommand();
        pCmd.CommandText = "SELECT Email FROM Rows;";
        var primaryCiphertext = ToHex(await pCmd.ExecuteScalarAsync());

        using var aCmd = auditConn.CreateCommand();
        aCmd.CommandText = "SELECT ActorEmail FROM Rows;";
        var auditCiphertext = ToHex(await aCmd.ExecuteScalarAsync());

        primaryCiphertext.Should().NotBe(auditCiphertext, "AES-GCM nonce is fresh per call so identical plaintext encrypts to distinct ciphertexts");
        primaryCiphertext.Should().NotContain(Convert.ToHexString(System.Text.Encoding.UTF8.GetBytes("shared@example.com")), "the plaintext must not leak into the column");
        auditCiphertext.Should().NotContain(Convert.ToHexString(System.Text.Encoding.UTF8.GetBytes("shared@example.com")), "the plaintext must not leak into the column");
    }

    private static string ToHex(object? scalar) => scalar switch
    {
        byte[] bytes => Convert.ToHexString(bytes),
        string s => Convert.ToHexString(System.Text.Encoding.UTF8.GetBytes(s)),
        _ => string.Empty,
    };

    [Fact]
    public async Task AddOrionVaultDbContext_shortcut_wires_UseOrionVault_inside_AddDbContext()
    {
        await using var sp = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(1, Key32B64));
                o.ActiveKeyId = 1;
            })
            .Services
            .AddOrionVaultDbContext<PrimaryCtx>((s, o) => o.UseSqlite(primaryConn))
            .BuildServiceProvider();

        using var scope = sp.CreateScope();
        var ctx = scope.ServiceProvider.GetRequiredService<PrimaryCtx>();
        await ctx.Database.EnsureCreatedAsync();
        ctx.Rows.Add(new PrimaryRow { Id = Guid.NewGuid(), Name = "Carol", Email = "carol@example.com" });
        await ctx.SaveChangesAsync();

        var roundTrip = await ctx.Rows.SingleAsync();
        roundTrip.Email.Should().Be("carol@example.com");
    }

    [Fact]
    public async Task AddOrionVaultDbContext_rejects_null_configure_callback()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
        {
            await using var _ = new ServiceCollection()
                .AddOrionVault(o =>
                {
                    o.UseStaticKeys(k => k.Add(1, Key32B64));
                    o.ActiveKeyId = 1;
                })
                .Services
                .AddOrionVaultDbContext<PrimaryCtx>(null!)
                .BuildServiceProvider();
            await Task.CompletedTask;
        });
    }
}
