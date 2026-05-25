namespace Moongazing.OrionVault.EntityFrameworkCore.Tests;

using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;
using Xunit;

public sealed class EndToEndEncryptionTests : IDisposable
{
    private const string Key32B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    private readonly SqliteConnection _conn;

    public class Customer
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = null!;
        [Encrypted] public string Email { get; set; } = null!;
#pragma warning disable CA1819 // Properties should not return arrays - this is a test fixture entity.
        [Encrypted] public byte[]? IdScan { get; set; }
#pragma warning restore CA1819
    }

    public class TestCtx : DbContext
    {
        public TestCtx(DbContextOptions opt) : base(opt) { }
        public DbSet<Customer> Customers => Set<Customer>();
    }

    public EndToEndEncryptionTests()
    {
        _conn = new SqliteConnection("Filename=:memory:");
        _conn.Open();
    }

    public void Dispose() => _conn.Dispose();

    private ServiceProvider BuildServices() =>
        new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(1, Key32B64));
                o.ActiveKeyId = 1;
            })
            .UseEntityFrameworkCore<TestCtx>()
            .Services
            .AddDbContext<TestCtx>((sp, o) => o.UseSqlite(_conn).UseOrionVault(sp))
            .BuildServiceProvider();

    [Fact]
    public async Task Encrypted_string_column_round_trips_through_SQLite()
    {
        await using var sp = BuildServices();
        using var scope = sp.CreateScope();
        var ctx = scope.ServiceProvider.GetRequiredService<TestCtx>();
        await ctx.Database.EnsureCreatedAsync();

        var id = Guid.NewGuid();
        ctx.Customers.Add(new Customer { Id = id, Name = "Ali", Email = "ali@example.com" });
        await ctx.SaveChangesAsync();
        ctx.ChangeTracker.Clear();

        // SqlQuery<T> for scalar element types expects the column to be named "Value"; alias accordingly.
        var raw = await ctx.Database.SqlQuery<byte[]>($"SELECT Email AS Value FROM Customers WHERE Id = {id}").SingleAsync();
        raw[0].Should().Be(0);
        raw[1].Should().Be(1);
        raw.Length.Should().Be(30 + System.Text.Encoding.UTF8.GetByteCount("ali@example.com"));

        var loaded = await ctx.Customers.SingleAsync(c => c.Id == id);
        loaded.Email.Should().Be("ali@example.com");
    }

    [Fact]
    public async Task Encrypted_bytes_column_round_trips()
    {
        await using var sp = BuildServices();
        using var scope = sp.CreateScope();
        var ctx = scope.ServiceProvider.GetRequiredService<TestCtx>();
        await ctx.Database.EnsureCreatedAsync();

        var id = Guid.NewGuid();
        var payload = new byte[] { 9, 8, 7, 6, 5 };
        ctx.Customers.Add(new Customer { Id = id, Name = "Veli", Email = "v@x.com", IdScan = payload });
        await ctx.SaveChangesAsync();
        ctx.ChangeTracker.Clear();

        var loaded = await ctx.Customers.SingleAsync(c => c.Id == id);
        loaded.IdScan.Should().Equal(payload);
    }

    [Fact]
    public async Task Null_encrypted_column_stays_null()
    {
        await using var sp = BuildServices();
        using var scope = sp.CreateScope();
        var ctx = scope.ServiceProvider.GetRequiredService<TestCtx>();
        await ctx.Database.EnsureCreatedAsync();

        var id = Guid.NewGuid();
        ctx.Customers.Add(new Customer { Id = id, Name = "Z", Email = "z@x.com", IdScan = null });
        await ctx.SaveChangesAsync();
        ctx.ChangeTracker.Clear();

        var loaded = await ctx.Customers.SingleAsync(c => c.Id == id);
        loaded.IdScan.Should().BeNull();
    }
}
