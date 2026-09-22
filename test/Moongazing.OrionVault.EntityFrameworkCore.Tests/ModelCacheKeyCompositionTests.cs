namespace Moongazing.OrionVault.EntityFrameworkCore.Tests;

using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;
using Moongazing.OrionVault.Exceptions;
using Xunit;

/// <summary>
/// Pins that OrionVault's <see cref="IModelCacheKeyFactory"/> replacement COMPOSES with one the
/// application already made, rather than displacing it.
/// <para>
/// <c>ReplaceService</c> keys its replacements on the service type alone, so two calls for
/// <see cref="IModelCacheKeyFactory"/> leave only the last one - the earlier implementation is gone
/// from the options and from the built container. An application that discriminates its model on its
/// own dimension (a table or schema per tenant, the usual reason, and the same audience as this
/// library) would silently lose it and serve one tenant's model to another.
/// </para>
/// <para>
/// <see cref="EncryptedModelCacheTests"/> covers OrionVault's own dimension in isolation; this covers
/// the two dimensions together, and what happens when the application replaces the service in the
/// order that cannot be composed.
/// </para>
/// </summary>
public sealed class ModelCacheKeyCompositionTests : IDisposable
{
    private static readonly string TenantAKeyB64 = Convert.ToBase64String(FillKey(0x33));
    private static readonly string TenantBKeyB64 = Convert.ToBase64String(FillKey(0x44));

    private readonly SqliteConnection conn;

    public ModelCacheKeyCompositionTests()
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

    /// <summary>
    /// The application's model dimension: which table the entity maps to. OrionVault knows nothing
    /// about it, which is exactly the point.
    /// </summary>
    private static string CurrentTable = "Rows";

    public class Row
    {
        public Guid Id { get; set; }
        [Encrypted] public string Secret { get; set; } = null!;
    }

    /// <summary>Own context type, so a cached model from this class cannot reach another one.</summary>
    public class PerTableCtx : DbContext
    {
        public PerTableCtx(DbContextOptions opt) : base(opt) { }

        public DbSet<Row> Rows => Set<Row>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            ArgumentNullException.ThrowIfNull(modelBuilder);
            modelBuilder.Entity<Row>().ToTable(CurrentTable);
        }
    }

    /// <summary>What an application replacing the factory looks like: it keys on its own dimension.</summary>
    public sealed class PerTableModelCacheKeyFactory : IModelCacheKeyFactory
    {
        public object Create(DbContext context, bool designTime)
        {
            ArgumentNullException.ThrowIfNull(context);
            return (context.GetType(), designTime, CurrentTable);
        }
    }

    private ServiceProvider BuildHost(string keyB64, bool replaceBeforeOrionVault) =>
        new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(1, keyB64));
                o.ActiveKeyId = 1;
            })
            .UseEntityFrameworkCore<PerTableCtx>()
            .Services
            .AddDbContext<PerTableCtx>((sp, o) =>
            {
                o.UseSqlite(conn);
                if (replaceBeforeOrionVault)
                {
                    o.ReplaceService<IModelCacheKeyFactory, PerTableModelCacheKeyFactory>();
                    o.UseOrionVault(sp);
                }
                else
                {
                    o.UseOrionVault(sp);
                    o.ReplaceService<IModelCacheKeyFactory, PerTableModelCacheKeyFactory>();
                }
            })
            .BuildServiceProvider();

    private static PerTableCtx Resolve(ServiceProvider sp, IServiceScope scope) =>
        scope.ServiceProvider.GetRequiredService<PerTableCtx>();

    /// <summary>
    /// The application's dimension survives OrionVault's replacement.
    /// <para>
    /// Both contexts come out of ONE container, so they share one key provider instance and
    /// OrionVault's own dimension of the key is identical for the two. Only the application's factory
    /// can tell them apart - which is precisely what makes this a test of composition rather than of
    /// OrionVault's discrimination. Drop the composition and the second context is served the first's
    /// model and reports the first's table.
    /// </para>
    /// </summary>
    [Fact]
    public void An_application_factorys_own_dimension_still_discriminates_after_UseOrionVault()
    {
        using var host = BuildHost(TenantAKeyB64, replaceBeforeOrionVault: true);

        CurrentTable = "Alpha";
        using var alphaScope = host.CreateScope();
        var alphaTable = Resolve(host, alphaScope).Model.FindEntityType(typeof(Row))!.GetTableName();

        CurrentTable = "Beta";
        using var betaScope = host.CreateScope();
        var betaTable = Resolve(host, betaScope).Model.FindEntityType(typeof(Row))!.GetTableName();

        alphaTable.Should().Be("Alpha");
        betaTable.Should().Be(
            "Beta",
            "the application's factory still discriminates; a replaced-away factory would have served Alpha's model");
    }

    /// <summary>
    /// OrionVault's dimension survives too. Two hosts agreeing on the application's dimension but
    /// holding DIFFERENT keys must not share a model, because the model carries the encryptor.
    /// </summary>
    [Fact]
    public void OrionVaults_dimension_still_discriminates_alongside_an_application_factory()
    {
        CurrentTable = "Shared";

        using var firstHost = BuildHost(TenantAKeyB64, replaceBeforeOrionVault: true);
        using var firstScope = firstHost.CreateScope();
        var firstModel = Resolve(firstHost, firstScope).Model;

        using var secondHost = BuildHost(TenantBKeyB64, replaceBeforeOrionVault: true);
        using var secondScope = secondHost.CreateScope();
        var secondModel = Resolve(secondHost, secondScope).Model;

        secondModel.Should().NotBeSameAs(
            firstModel,
            "the two hosts hold different key material, so they must not share converters");
    }

    /// <summary>
    /// The order that cannot be composed: replacing the factory AFTER UseOrionVault overwrites
    /// OrionVault's, and the options keep no record that it happened. Rather than let the key
    /// discrimination go silently missing - the cross-tenant leak this whole factory exists to close
    /// - the model refuses to build and the message says which way round to wire it.
    /// </summary>
    [Fact]
    public void Replacing_the_factory_after_UseOrionVault_refuses_to_build_the_model()
    {
        CurrentTable = "Late";
        using var host = BuildHost(TenantAKeyB64, replaceBeforeOrionVault: false);
        using var scope = host.CreateScope();
        var ctx = Resolve(host, scope);

        var build = () => ctx.Model.FindEntityType(typeof(Row));

        var refusal = build.Should().Throw<OrionVaultConfigurationException>().And;
        refusal.Message.Should().Contain("PerTableModelCacheKeyFactory", "the message must name what displaced it");
        refusal.Message.Should().Contain("BEFORE UseOrionVault", "and say which way round to wire it");
    }
}
