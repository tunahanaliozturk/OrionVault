namespace Moongazing.OrionVault.EntityFrameworkCore.Tests;

using System.Text;

using FluentAssertions;

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;
using Moongazing.OrionVault.Exceptions;

using Xunit;

/// <summary>
/// End-to-end coverage (real SQLite in-memory, real model customizer + configurator) for the
/// v0.3.3 feature: encrypting an EF property that carries a value converter to a supported
/// provider type (string or byte[]). The OrionVault encryption converter is COMPOSED on top of
/// the consumer's existing converter, so the column stores the encrypted form of the converted
/// provider value and reads run decrypt -> the existing FromProvider.
/// </summary>
public sealed class ValueConvertedEncryptionTests : IDisposable
{
    private const string Key32B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    private readonly SqliteConnection _conn;

    public ValueConvertedEncryptionTests()
    {
        _conn = new SqliteConnection("Filename=:memory:");
        _conn.Open();
    }

    public void Dispose() => _conn.Dispose();

    // A value object mapped to a string column. The real consumer trigger: a national-id wrapper
    // flagged [Encrypted] and mapped via HasConversion(v => v.Value, s => new Tckn(s)).
    public sealed record Tckn(string Value);

    // A value object mapped to a byte[] column.
#pragma warning disable CA1819 // Properties should not return arrays - test fixture value object.
    public sealed record Badge(byte[] Value);
#pragma warning restore CA1819

    // A value object whose converter targets an UNSUPPORTED provider type (int). OrionVault must
    // still reject it with the original "does not support" diagnostic.
    public sealed record Score(int Value);

    public sealed class Customer
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = null!;
        [Encrypted] public Tckn NationalId { get; set; } = null!;
#pragma warning disable CA1819 // Properties should not return arrays - test fixture value object.
        [Encrypted] public Badge? Badge { get; set; }
#pragma warning restore CA1819
    }

    public sealed class CustomerCtx : DbContext
    {
        public CustomerCtx(DbContextOptions opt) : base(opt) { }
        public DbSet<Customer> Customers => Set<Customer>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            ArgumentNullException.ThrowIfNull(modelBuilder);
            var customer = modelBuilder.Entity<Customer>();
            // Value object -> string. The [Encrypted] attribute flags it; OrionVault composes its
            // encryption converter on top of this one.
            customer.Property(c => c.NationalId)
                .HasConversion(v => v.Value, s => new Tckn(s));
            // Value object -> byte[].
            customer.Property(c => c.Badge)
                .HasConversion(v => v!.Value, b => new Badge(b));
        }
    }

    public sealed class BadCustomer
    {
        public Guid Id { get; set; }
        [Encrypted] public Score Score { get; set; } = null!;
    }

    public sealed class BadCustomerCtx : DbContext
    {
        public BadCustomerCtx(DbContextOptions opt) : base(opt) { }
        public DbSet<BadCustomer> Customers => Set<BadCustomer>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            ArgumentNullException.ThrowIfNull(modelBuilder);
            modelBuilder.Entity<BadCustomer>()
                .Property(c => c.Score)
                .HasConversion(v => v.Value, i => new Score(i));
        }
    }

    private ServiceProvider BuildServices<TCtx>() where TCtx : DbContext =>
        new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(1, Key32B64));
                o.ActiveKeyId = 1;
            })
            .UseEntityFrameworkCore<TCtx>()
            .Services
            .AddDbContext<TCtx>((sp, o) => o.UseSqlite(_conn).UseOrionVault(sp))
            .BuildServiceProvider();

    [Fact]
    public async Task Value_object_mapped_to_string_round_trips_and_is_stored_as_ciphertext()
    {
        await using var sp = BuildServices<CustomerCtx>();
        using var scope = sp.CreateScope();
        var ctx = scope.ServiceProvider.GetRequiredService<CustomerCtx>();
        await ctx.Database.EnsureCreatedAsync();

        const string plaintext = "12345678901";
        var id = Guid.NewGuid();
        ctx.Customers.Add(new Customer { Id = id, Name = "Ali", NationalId = new Tckn(plaintext) });
        await ctx.SaveChangesAsync();
        ctx.ChangeTracker.Clear();

        // At-rest: the stored column is the AES-GCM envelope of the CONVERTED provider value
        // (the string), not the plaintext. Header is [keyId(2 BE) | nonce(12) | tag(16) | ct],
        // so byte[0]=0, byte[1]=1 (key id 1) and the total length is 30 fixed overhead + the
        // UTF-8 byte count of the provider string. SqlQuery<T> for a scalar expects "Value".
        var raw = await ctx.Database
            .SqlQuery<byte[]>($"SELECT NationalId AS Value FROM Customers WHERE Id = {id}")
            .SingleAsync();
        raw[0].Should().Be(0);
        raw[1].Should().Be(1);
        raw.Length.Should().Be(30 + Encoding.UTF8.GetByteCount(plaintext));

        // And it genuinely decrypts back to the plaintext provider string via the encryptor.
        var encryptor = sp.GetRequiredService<IEncryptor>();
        encryptor.DecryptString(raw).Should().Be(plaintext);

        // Round-trip: reading returns an equal value object.
        var loaded = await ctx.Customers.SingleAsync(c => c.Id == id);
        loaded.NationalId.Should().Be(new Tckn(plaintext));
    }

    [Fact]
    public async Task Value_object_mapped_to_bytes_round_trips_and_is_stored_as_ciphertext()
    {
        await using var sp = BuildServices<CustomerCtx>();
        using var scope = sp.CreateScope();
        var ctx = scope.ServiceProvider.GetRequiredService<CustomerCtx>();
        await ctx.Database.EnsureCreatedAsync();

        var payload = new byte[] { 9, 8, 7, 6, 5 };
        var id = Guid.NewGuid();
        ctx.Customers.Add(new Customer
        {
            Id = id,
            Name = "Veli",
            NationalId = new Tckn("00000000000"),
            Badge = new Badge(payload),
        });
        await ctx.SaveChangesAsync();
        ctx.ChangeTracker.Clear();

        var raw = await ctx.Database
            .SqlQuery<byte[]>($"SELECT Badge AS Value FROM Customers WHERE Id = {id}")
            .SingleAsync();
        raw[0].Should().Be(0);
        raw[1].Should().Be(1);
        raw.Length.Should().Be(30 + payload.Length);

        var encryptor = sp.GetRequiredService<IEncryptor>();
        encryptor.DecryptBytes(raw).Should().Equal(payload);

        var loaded = await ctx.Customers.SingleAsync(c => c.Id == id);
        loaded.Badge!.Value.Should().Equal(payload);
    }

    [Fact]
    public async Task Value_object_with_converter_to_unsupported_provider_type_still_throws()
    {
        await using var sp = BuildServices<BadCustomerCtx>();
        using var scope = sp.CreateScope();
        var ctx = scope.ServiceProvider.GetRequiredService<BadCustomerCtx>();

        // Model build runs the OrionVault configurator; a converter to int is not a supported
        // provider type, so the original "does not support" diagnostic must fire on first build.
        var act = async () => await ctx.Database.EnsureCreatedAsync();
        await act.Should().ThrowAsync<OrionVaultConfigurationException>()
            .WithMessage("*Score*");
    }
}
