namespace Moongazing.OrionVault.EntityFrameworkCore.Tests;

using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;
using Xunit;

/// <summary>
/// Pins key isolation across EF Core's compiled-model cache. The encryption value converters
/// capture a specific <see cref="IEncryptor"/> by closure, and the converters live on the compiled
/// model; EF Core's default <c>IModelCacheKeyFactory</c> keys that model on the DbContext CLR type
/// alone, and <c>src/</c> ships no replacement. Two hosts bound to DIFFERENT key material over the
/// SAME context type therefore risk sharing whichever host compiled the model first.
/// <para>
/// <see cref="MultiDbContextTests"/> covers two DIFFERENT context types sharing one encryptor, and
/// <see cref="KeyedEncryptorBindingTests"/> covers the DI registrations in isolation (no model is
/// ever built there). Neither covers this case, which is why it lives in its own class - with its
/// own DbContext type, because EF Core's model cache is process-wide and a poisoned entry would
/// leak into any other test sharing the type.
/// </para>
/// </summary>
public sealed class EncryptedModelCacheTests : IDisposable
{
    private static readonly string TenantAKeyB64 = Convert.ToBase64String(FillKey(0x11));
    private static readonly string TenantBKeyB64 = Convert.ToBase64String(FillKey(0x22));

    private readonly SqliteConnection conn;

    public EncryptedModelCacheTests()
    {
        conn = new SqliteConnection("Filename=:memory:");
        conn.Open();
    }

    public void Dispose() => conn.Dispose();

    private static byte[] FillKey(byte seed)
    {
        var key = new byte[32];
        Array.Fill(key, seed);
        return key;
    }

    public class Secret
    {
        public Guid Id { get; set; }
        public string Label { get; set; } = null!;
        [Encrypted] public string Value { get; set; } = null!;
    }

    /// <summary>Used by this class only, so the poisoned model-cache entry cannot escape it.</summary>
    public class TenantCtx : DbContext
    {
        public TenantCtx(DbContextOptions opt) : base(opt) { }
        public DbSet<Secret> Secrets => Set<Secret>();
    }

    private ServiceProvider BuildTenantHost(string keyB64) =>
        new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(1, keyB64));
                o.ActiveKeyId = 1;
            })
            .UseEntityFrameworkCore<TenantCtx>()
            .Services
            .AddDbContext<TenantCtx>((sp, o) => o.UseSqlite(conn).UseOrionVault(sp))
            .BuildServiceProvider();

    /// <summary>
    /// FAILING - DOCUMENTS A DEFECT. Tenant A writes a secret under its own key. Tenant B, wired to
    /// completely different key material but using the same DbContext CLR type, must NOT be able to
    /// read it: its key cannot open tenant A's AES-GCM envelope. Today the second host reuses the
    /// compiled model tenant A built - converters and captured encryptor included - so the read
    /// succeeds and returns tenant A's plaintext, silently defeating per-tenant key isolation.
    /// </summary>
    [Fact]
    public async Task A_second_host_with_different_keys_cannot_read_the_first_hosts_ciphertext()
    {
        const string plaintext = "tenant-a-only@example.com";

        await using var tenantA = BuildTenantHost(TenantAKeyB64);
        using (var scopeA = tenantA.CreateScope())
        {
            var ctxA = scopeA.ServiceProvider.GetRequiredService<TenantCtx>();
            await ctxA.Database.EnsureCreatedAsync();
            ctxA.Secrets.Add(new Secret { Id = Guid.NewGuid(), Label = "a", Value = plaintext });
            await ctxA.SaveChangesAsync();
        }

        await using var tenantB = BuildTenantHost(TenantBKeyB64);

        // Guard: the two hosts really do hold different key material, so a pass below cannot be a
        // false negative caused by the fixture handing out the same key twice.
        using (var guardA = tenantA.CreateScope())
        using (var guardB = tenantB.CreateScope())
        {
            var encryptorA = guardA.ServiceProvider.GetRequiredService<IEncryptor>();
            var encryptorB = guardB.ServiceProvider.GetRequiredService<IEncryptor>();
            var cipherFromA = encryptorA.EncryptString(plaintext);
            Assert.ThrowsAny<Exception>(() => encryptorB.DecryptString(cipherFromA));
        }

        using var scopeB = tenantB.CreateScope();
        var ctxB = scopeB.ServiceProvider.GetRequiredService<TenantCtx>();

        var read = async () => await ctxB.Secrets.SingleAsync();
        (await read.Should().ThrowAsync<Exception>(
            "tenant B's key cannot open tenant A's envelope; a shared compiled model would leak tenant A's encryptor"))
            .And.Should().NotBeNull();
    }
}
