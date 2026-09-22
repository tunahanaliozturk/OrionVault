namespace Moongazing.OrionVault.EntityFrameworkCore.Tests;

using System.ComponentModel.DataAnnotations;
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;
using Xunit;

/// <summary>
/// What OrionVault's model customizer does to the SHAPE of an encrypted property: how wide the
/// column ends up once the envelope is accounted for.
/// <see cref="EncryptedColumnBehaviourTests"/> covers the store-facing behaviour and the minimum the
/// widened facet has to satisfy; this pins the arithmetic itself, because the UTF-8 expansion is the
/// part that is easy to get wrong.
/// </summary>
public sealed class EncryptedModelShapeTests : IDisposable
{
    private const string Key32B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    private const int EnvelopeOverhead = 30;

    private readonly SqliteConnection conn;

    public EncryptedModelShapeTests()
    {
        conn = new SqliteConnection("Filename=:memory:");
        conn.Open();
    }

    public void Dispose() => conn.Dispose();

    private ServiceProvider BuildHost<TContext>()
        where TContext : DbContext =>
        new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(1, Key32B64));
                o.ActiveKeyId = 1;
            })
            .UseEntityFrameworkCore<TContext>()
            .Services
            .AddDbContext<TContext>((sp, o) => o.UseSqlite(conn).UseOrionVault(sp))
            .BuildServiceProvider();

    // ---------------------------------------------------------------------------------------
    // The widened facet.
    // ---------------------------------------------------------------------------------------

    public class Sized
    {
        public Guid Id { get; set; }

        [Encrypted]
        [MaxLength(64)]
        public string Text { get; set; } = null!;

#pragma warning disable CA1819 // Properties should not return arrays - test fixture entity.
        [Encrypted]
        [MaxLength(64)]
        public byte[]? Blob { get; set; }
#pragma warning restore CA1819

        [Encrypted]
        public string? Unbounded { get; set; }
    }

    public class SizedCtx : DbContext
    {
        public SizedCtx(DbContextOptions opt) : base(opt) { }

        public DbSet<Sized> Rows => Set<Sized>();
    }

    /// <summary>
    /// The widening arithmetic, per provider type. A string's MaxLength is in CHARACTERS and the
    /// plaintext is UTF-8 BYTES, so the worst case is three bytes per character plus room for a
    /// dangling surrogate (<c>Encoding.UTF8.GetMaxByteCount</c>); a byte[]'s MaxLength is already in
    /// bytes and only the envelope is added. An unbounded column stays unbounded.
    /// </summary>
    [Fact]
    public void MaxLength_is_widened_per_provider_type_and_unbounded_columns_stay_unbounded()
    {
        using var sp = BuildHost<SizedCtx>();
        using var scope = sp.CreateScope();
        var entity = scope.ServiceProvider.GetRequiredService<SizedCtx>()
            .Model.FindEntityType(typeof(Sized))!;

        entity.FindProperty(nameof(Sized.Text))!.GetMaxLength().Should().Be(
            EnvelopeOverhead + System.Text.Encoding.UTF8.GetMaxByteCount(64),
            "64 characters is up to 3*64+3 UTF-8 bytes, and the envelope adds 30 on top");

        entity.FindProperty(nameof(Sized.Blob))!.GetMaxLength().Should().Be(
            EnvelopeOverhead + 64,
            "a byte[] facet is already in bytes, so only the envelope is added");

        entity.FindProperty(nameof(Sized.Unbounded))!.GetMaxLength().Should().BeNull(
            "a column the consumer left unbounded has nothing to overflow");
    }
}
