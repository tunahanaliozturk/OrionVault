namespace Moongazing.OrionVault.EntityFrameworkCore.Tests;

using System.ComponentModel.DataAnnotations;
using System.Data.Common;
using System.Text;
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;
using Moongazing.OrionVault.Exceptions;
using Xunit;

/// <summary>
/// Pins the store-facing behaviour of an encrypted column on a real SQLite database: what the
/// declared <see cref="MaxLengthAttribute"/> means once the envelope is added, whether an
/// untouched row is rewritten on save, how null and empty values survive a round trip, that a
/// unique index over a randomised ciphertext is refused at model build, and what a LINQ filter over
/// an encrypted column actually emits and returns.
/// <para>
/// Shape follows <see cref="EndToEndEncryptionTests"/>: one open in-memory SQLite connection per
/// test class instance, hosts built through the normal <c>AddOrionVault().UseEntityFrameworkCore</c>
/// wiring, raw ciphertext read back over the same connection.
/// </para>
/// </summary>
public sealed class EncryptedColumnBehaviourTests : IDisposable
{
    private const string Key32B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /// <summary>Fixed AES-GCM envelope overhead: [keyId:2 | nonce:12 | tag:16].</summary>
    private const int EnvelopeOverhead = 30;

    private readonly SqliteConnection conn;

    public EncryptedColumnBehaviourTests()
    {
        conn = new SqliteConnection("Filename=:memory:");
        conn.Open();
    }

    public void Dispose() => conn.Dispose();

    public class Person
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = null!;

        // 64 is the CONSUMER's intent for the plaintext. Nothing widens it for the envelope.
        [Encrypted]
        [MaxLength(64)]
        public string Email { get; set; } = null!;

        [Encrypted] public string? Nickname { get; set; }

#pragma warning disable CA1819 // Properties should not return arrays - test fixture entity.
        [Encrypted] public byte[]? Photo { get; set; }
#pragma warning restore CA1819
    }

    public class PeopleCtx : DbContext
    {
        public PeopleCtx(DbContextOptions opt) : base(opt) { }

        public DbSet<Person> People => Set<Person>();

        // The unique index the consumer would reach for lives in UniquePeopleCtx below, because it is
        // now REFUSED at model build - see
        // A_unique_index_on_an_encrypted_column_is_refused_at_model_build. Keeping it here would stop
        // every other test in this class from building its model.
    }

    /// <summary>The consumer's stated invariant - one row per e-mail address - written the way that no longer builds.</summary>
    public class UniquePeopleCtx : DbContext
    {
        public UniquePeopleCtx(DbContextOptions opt) : base(opt) { }

        public DbSet<Person> People => Set<Person>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            ArgumentNullException.ThrowIfNull(modelBuilder);
            modelBuilder.Entity<Person>().HasIndex(p => p.Email).IsUnique();
        }
    }

    /// <summary>Records every SQL statement EF Core sends, so a test can assert what was NOT sent.</summary>
    private sealed class CommandCapture : DbCommandInterceptor
    {
        public List<string> Commands { get; } = [];

        private void Record(DbCommand command) => Commands.Add(command.CommandText);

        public override InterceptionResult<DbDataReader> ReaderExecuting(
            DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result)
        {
            Record(command);
            return result;
        }

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            Record(command);
            return ValueTask.FromResult(result);
        }

        public override InterceptionResult<int> NonQueryExecuting(
            DbCommand command, CommandEventData eventData, InterceptionResult<int> result)
        {
            Record(command);
            return result;
        }

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command, CommandEventData eventData, InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            Record(command);
            return ValueTask.FromResult(result);
        }

        public override InterceptionResult<object> ScalarExecuting(
            DbCommand command, CommandEventData eventData, InterceptionResult<object> result)
        {
            Record(command);
            return result;
        }

        public override ValueTask<InterceptionResult<object>> ScalarExecutingAsync(
            DbCommand command, CommandEventData eventData, InterceptionResult<object> result,
            CancellationToken cancellationToken = default)
        {
            Record(command);
            return ValueTask.FromResult(result);
        }
    }

    private ServiceProvider BuildHost(CommandCapture? capture = null) =>
        new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(1, Key32B64));
                o.ActiveKeyId = 1;
            })
            .UseEntityFrameworkCore<PeopleCtx>()
            .Services
            .AddDbContext<PeopleCtx>((sp, o) =>
            {
                o.UseSqlite(conn).UseOrionVault(sp);
                if (capture is not null)
                {
                    o.AddInterceptors(capture);
                }
            })
            .BuildServiceProvider();

    private enum Column
    {
        Email,
        Nickname,
        Photo,
    }

    /// <summary>Reads the on-disk bytes of one column straight off the connection, bypassing EF.</summary>
    private byte[]? RawColumn(Column column, string name)
    {
        using var cmd = conn.CreateCommand();
        // Constant SQL per column (no interpolation) so the statement is never assembled from input;
        // CA2100 only sees a non-literal expression here and cannot tell the arms are all constants.
#pragma warning disable CA2100
        cmd.CommandText = column switch
        {
            Column.Email => "SELECT Email FROM People WHERE Name = $name;",
            Column.Nickname => "SELECT Nickname FROM People WHERE Name = $name;",
            Column.Photo => "SELECT Photo FROM People WHERE Name = $name;",
            _ => throw new ArgumentOutOfRangeException(nameof(column)),
        };
#pragma warning restore CA2100
        cmd.Parameters.AddWithValue("$name", name);
        var value = cmd.ExecuteScalar();
        return value as byte[];
    }

    // ---------------------------------------------------------------------------------------
    // 1. MaxLength vs. the envelope.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// FAILING - DOCUMENTS A DEFECT. <c>EncryptionConfigurator</c> attaches the encryption value
    /// converter but never calls <c>SetMaxLength</c>, so a column the consumer declared as
    /// <c>MaxLength(64)</c> for 64 characters of plaintext is still declared as 64 on the store
    /// while it now has to hold 30 + N envelope bytes. On a length-enforcing provider
    /// (<c>varbinary(64)</c> on SQL Server, <c>VARBINARY(64)</c> on MySQL) the write of a 40
    /// character value needs 70 bytes and does not fit. The assertion below is the invariant any
    /// fix must satisfy: the store length must cover the envelope for a plaintext of the declared
    /// maximum size.
    /// </summary>
    [Fact]
    public async Task MaxLength_on_an_encrypted_column_leaves_room_for_the_encryption_envelope()
    {
        await using var sp = BuildHost();
        using var scope = sp.CreateScope();
        var ctx = scope.ServiceProvider.GetRequiredService<PeopleCtx>();
        await ctx.Database.EnsureCreatedAsync();

        var email = ctx.Model.FindEntityType(typeof(Person))!.FindProperty(nameof(Person.Email))!;

        email.GetValueConverter().Should().NotBeNull("the property is [Encrypted] so a converter is attached");
        email.GetMaxLength().Should().NotBeNull("the property declares [MaxLength(64)]");

        // The column now stores ciphertext, so its declared length has to cover the envelope of a
        // maximum-length plaintext, not the plaintext itself.
        email.GetMaxLength()!.Value.Should().BeGreaterThanOrEqualTo(
            EnvelopeOverhead + 64,
            "the encrypted column must be able to hold the envelope of a 64-byte plaintext");
    }

    /// <summary>
    /// The concrete overflow the previous test describes, measured end to end: a 40-character
    /// value produces 70 stored bytes against a column the model still calls 64 wide.
    /// SQLite has no length enforcement at all (a declared length on a BLOB is ignored), so here
    /// the row is neither rejected nor truncated - it simply round-trips. The behaviour on a
    /// length-enforcing provider is NOT settled by this test; see the class remarks.
    /// </summary>
    [Fact]
    public async Task An_oversized_envelope_is_stored_whole_on_SQLite_because_SQLite_ignores_column_length()
    {
        await using var sp = BuildHost();
        using var scope = sp.CreateScope();
        var ctx = scope.ServiceProvider.GetRequiredService<PeopleCtx>();
        await ctx.Database.EnsureCreatedAsync();

        var plaintext = new string('a', 40); // 40 ASCII bytes -> 70 bytes once enveloped.
        ctx.People.Add(new Person { Id = Guid.NewGuid(), Name = "overflow", Email = plaintext });
        await ctx.SaveChangesAsync();
        ctx.ChangeTracker.Clear();

        var stored = RawColumn(Column.Email, "overflow");
        stored.Should().NotBeNull();
        stored!.Length.Should().Be(EnvelopeOverhead + 40);
        stored.Length.Should().BeGreaterThan(64, "the envelope overflows the declared MaxLength(64)");

        // Nothing was lost: SQLite stored all 70 bytes, so the value still decrypts. A store that
        // truncated instead would have destroyed the AES-GCM tag and made the row undecryptable
        // with any key.
        var loaded = await ctx.People.SingleAsync(p => p.Name == "overflow");
        loaded.Email.Should().Be(plaintext);
    }

    // ---------------------------------------------------------------------------------------
    // 2. Change detection.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// An unmodified encrypted row must not be rewritten on save. If it were, every SaveChanges
    /// would burn a fresh nonce on every encrypted row and the rotation runner's
    /// "already on the active key -> skip" logic would be pointless.
    /// </summary>
    [Fact]
    public async Task SaveChanges_emits_no_UPDATE_for_encrypted_rows_that_were_only_loaded()
    {
        var capture = new CommandCapture();
        await using var sp = BuildHost(capture);
        using var scope = sp.CreateScope();
        var ctx = scope.ServiceProvider.GetRequiredService<PeopleCtx>();
        await ctx.Database.EnsureCreatedAsync();

        for (var i = 0; i < 3; i++)
        {
            ctx.People.Add(new Person
            {
                Id = Guid.NewGuid(),
                Name = $"idle{i}",
                Email = $"idle{i}@example.com",
                Photo = [1, 2, 3],
            });
        }

        await ctx.SaveChangesAsync();
        ctx.ChangeTracker.Clear();

        var before = new[] { RawColumn(Column.Email, "idle0"), RawColumn(Column.Email, "idle1"), RawColumn(Column.Email, "idle2") };

        var loaded = await ctx.People.ToListAsync();
        loaded.Should().HaveCount(3);

        capture.Commands.Clear();
        var written = await ctx.SaveChangesAsync();

        written.Should().Be(0, "nothing was mutated");
        capture.Commands.Should().NotContain(c => c.Contains("UPDATE", StringComparison.OrdinalIgnoreCase));

        // Byte-for-byte proof: a rewrite would have produced a different nonce.
        RawColumn(Column.Email, "idle0").Should().Equal(before[0]);
        RawColumn(Column.Email, "idle1").Should().Equal(before[1]);
        RawColumn(Column.Email, "idle2").Should().Equal(before[2]);
    }

    // ---------------------------------------------------------------------------------------
    // 3. Null vs. empty.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// EF Core skips value converters for null, so a null encrypted column stays null. An empty
    /// value is NOT null: it encrypts to exactly the 30-byte envelope and must come back as an
    /// empty string / empty array, never as null. Covered on both a string and a byte[] column.
    /// </summary>
    [Fact]
    public async Task Null_and_empty_encrypted_values_stay_distinguishable_across_a_round_trip()
    {
        await using var sp = BuildHost();
        using var scope = sp.CreateScope();
        var ctx = scope.ServiceProvider.GetRequiredService<PeopleCtx>();
        await ctx.Database.EnsureCreatedAsync();

        ctx.People.Add(new Person
        {
            Id = Guid.NewGuid(),
            Name = "nulls",
            Email = "nulls@example.com",
            Nickname = null,
            Photo = null,
        });
        ctx.People.Add(new Person
        {
            Id = Guid.NewGuid(),
            Name = "empties",
            Email = "empties@example.com",
            Nickname = string.Empty,
            Photo = [],
        });
        await ctx.SaveChangesAsync();
        ctx.ChangeTracker.Clear();

        // On disk: null really is SQL NULL; empty really is a 30-byte envelope.
        RawColumn(Column.Nickname, "nulls").Should().BeNull();
        RawColumn(Column.Photo, "nulls").Should().BeNull();
        RawColumn(Column.Nickname, "empties").Should().NotBeNull().And.HaveCount(EnvelopeOverhead);
        RawColumn(Column.Photo, "empties").Should().NotBeNull().And.HaveCount(EnvelopeOverhead);

        var nulls = await ctx.People.SingleAsync(p => p.Name == "nulls");
        nulls.Nickname.Should().BeNull();
        nulls.Photo.Should().BeNull();

        var empties = await ctx.People.SingleAsync(p => p.Name == "empties");
        empties.Nickname.Should().NotBeNull("an empty encrypted string must not read back as null");
        empties.Nickname.Should().BeEmpty();
        empties.Photo.Should().NotBeNull("an empty encrypted byte[] must not read back as null");
        empties.Photo.Should().BeEmpty();
    }

    // ---------------------------------------------------------------------------------------
    // 4. Unique index.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// WAS A HAZARD NOTE, NOW AN ASSERTION. The index would be built over the ciphertext, and AES-GCM
    /// uses a fresh nonce per write, so two rows holding the same plaintext e-mail produce different
    /// ciphertexts and the unique index never fires: the uniqueness invariant a consumer believes
    /// <c>.IsUnique()</c> enforces is silently gone. This used to be pinned as the (accepted)
    /// behaviour - duplicates inserted, both read back. It is now refused at model build instead, and
    /// the message has to name the property and point at the blind index, which is the feature that
    /// IS deterministic and can carry the constraint.
    /// </summary>
    [Fact]
    public async Task A_unique_index_on_an_encrypted_column_is_refused_at_model_build()
    {
        await using var sp = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(1, Key32B64));
                o.ActiveKeyId = 1;
            })
            .UseEntityFrameworkCore<UniquePeopleCtx>()
            .Services
            .AddDbContext<UniquePeopleCtx>((s, o) => o.UseSqlite(conn).UseOrionVault(s))
            .BuildServiceProvider();

        using var scope = sp.CreateScope();
        var ctx = scope.ServiceProvider.GetRequiredService<UniquePeopleCtx>();

        // Touching the model is what builds it; the refusal has to land here, before any row exists.
        var build = () => ctx.Model.FindEntityType(typeof(Person));

        var refusal = build.Should().Throw<OrionVaultConfigurationException>()
            .WithMessage("*Person.Email*", "the message must name the offending property")
            .And;

        refusal.Message.Should().Contain("unique index", "the refusal has to say what is wrong");
        refusal.Message.Should().Contain(
            "blind-index", "it has to point at the OrionVault feature that CAN carry the constraint");
    }

    // ---------------------------------------------------------------------------------------
    // 5. Querying an encrypted column.
    // ---------------------------------------------------------------------------------------

    private static async Task<PeopleCtx> SeedOneAsync(IServiceScope scope, string name, string email)
    {
        var ctx = scope.ServiceProvider.GetRequiredService<PeopleCtx>();
        await ctx.Database.EnsureCreatedAsync();
        ctx.People.Add(new Person { Id = Guid.NewGuid(), Name = name, Email = email });
        await ctx.SaveChangesAsync();
        ctx.ChangeTracker.Clear();
        return ctx;
    }

    /// <summary>
    /// DOCUMENTS A HAZARD. Confirms the claim OV0002 makes: an equality filter over an encrypted
    /// column is translated to SQL, compares the probe's freshly-enveloped ciphertext against the
    /// row's own, and therefore matches nothing. It does not throw - the query reports success
    /// with zero rows.
    /// </summary>
    [Fact]
    public async Task Equality_filter_on_an_encrypted_column_matches_nothing_and_does_not_throw()
    {
        var capture = new CommandCapture();
        await using var sp = BuildHost(capture);
        using var scope = sp.CreateScope();
        var ctx = await SeedOneAsync(scope, "eq", "eq@example.com");

        capture.Commands.Clear();
        var hits = await ctx.People.Where(p => p.Email == "eq@example.com").ToListAsync();

        hits.Should().BeEmpty("the stored ciphertext can never equal a freshly encrypted probe");
        capture.Commands.Should().Contain(c => c.Contains("WHERE", StringComparison.OrdinalIgnoreCase),
            "the predicate is pushed to SQL rather than evaluated in memory");

        // The row is genuinely there; only the filter is worthless.
        (await ctx.People.CountAsync(p => p.Name == "eq")).Should().Be(1);
    }

    /// <summary>
    /// DOCUMENTS A HAZARD. <c>ExecuteDelete</c> over an encrypted column deletes nothing, returns
    /// 0, and raises nothing. A GDPR erasure written this way reports success while the subject's
    /// row is still in the table. OV0002 does flag the <c>Where</c> that precedes it (it is a
    /// <c>Queryable.Where</c> with an equality on an <c>[Encrypted]</c> property), but its message
    /// only says the comparison is always false - it does not say the erasure will claim success.
    /// </summary>
    [Fact]
    public async Task ExecuteDelete_filtered_by_an_encrypted_column_deletes_nothing_and_reports_success()
    {
        await using var sp = BuildHost();
        using var scope = sp.CreateScope();
        var ctx = await SeedOneAsync(scope, "erase", "erase@example.com");

        var deleted = await ctx.People.Where(p => p.Email == "erase@example.com").ExecuteDeleteAsync();

        deleted.Should().Be(0, "no stored ciphertext equals the probe");
        (await ctx.People.CountAsync(p => p.Name == "erase")).Should().Be(1, "the row the caller meant to erase survives");
    }

    /// <summary>
    /// DOCUMENTS A HAZARD: the same silent no-op for <c>ExecuteUpdate</c>.
    /// </summary>
    [Fact]
    public async Task ExecuteUpdate_filtered_by_an_encrypted_column_updates_nothing_and_reports_success()
    {
        await using var sp = BuildHost();
        using var scope = sp.CreateScope();
        var ctx = await SeedOneAsync(scope, "upd", "upd@example.com");

        var updated = await ctx.People
            .Where(p => p.Email == "upd@example.com")
            .ExecuteUpdateAsync(s => s.SetProperty(p => p.Name, "renamed"));

        updated.Should().Be(0);
        (await ctx.People.CountAsync(p => p.Name == "renamed")).Should().Be(0);
    }

    /// <summary>
    /// The safe half of <c>ExecuteUpdate</c>: SETTING an encrypted column goes through the value
    /// converter, so the new value is enveloped on the way in and still decrypts on read. Pinned
    /// because the opposite - writing the plaintext straight into the column - would be a silent
    /// disclosure.
    /// </summary>
    [Fact]
    public async Task ExecuteUpdate_setting_an_encrypted_column_writes_ciphertext_not_plaintext()
    {
        await using var sp = BuildHost();
        using var scope = sp.CreateScope();
        var ctx = await SeedOneAsync(scope, "setter", "before@example.com");

        var updated = await ctx.People
            .Where(p => p.Name == "setter")
            .ExecuteUpdateAsync(s => s.SetProperty(p => p.Email, "after@example.com"));

        updated.Should().Be(1);

        var stored = RawColumn(Column.Email, "setter");
        stored.Should().NotBeNull();
        stored!.Length.Should().Be(EnvelopeOverhead + Encoding.UTF8.GetByteCount("after@example.com"));
        Convert.ToHexString(stored).Should().NotContain(
            Convert.ToHexString(Encoding.UTF8.GetBytes("after@example.com")),
            "the plaintext must not reach the column");

        ctx.ChangeTracker.Clear();
        var loaded = await ctx.People.SingleAsync(p => p.Name == "setter");
        loaded.Email.Should().Be("after@example.com");
    }

    /// <summary>
    /// A projection that selects only the encrypted column still runs the read converter, so the
    /// caller gets plaintext rather than raw envelope bytes.
    /// </summary>
    [Fact]
    public async Task Projecting_only_the_encrypted_column_returns_decrypted_plaintext()
    {
        await using var sp = BuildHost();
        using var scope = sp.CreateScope();
        var ctx = await SeedOneAsync(scope, "proj", "proj@example.com");

        var emails = await ctx.People.Where(p => p.Name == "proj").Select(p => p.Email).ToListAsync();

        emails.Should().ContainSingle().Which.Should().Be("proj@example.com");
    }

    /// <summary>
    /// DOCUMENTS A HAZARD that OV0002 does NOT flag: <c>Contains</c> and <c>StartsWith</c> over an
    /// encrypted column are translated to SQL against the ciphertext and come back empty, with no
    /// warning at build time and no error at run time. The exact outcome is pinned rather than
    /// loosened to "empty or throws", so that any change in EF Core's translation gets a human
    /// look - refusing to translate would also be safe, but it is a different contract.
    /// </summary>
    [Fact]
    public async Task Substring_filters_on_an_encrypted_column_match_nothing_and_do_not_throw()
    {
        await using var sp = BuildHost();
        using var scope = sp.CreateScope();
        var ctx = await SeedOneAsync(scope, "sub", "substring@example.com");

        // What must never happen is a row coming back - that would mean the predicate ran against
        // something other than the randomised ciphertext.
        (await DescribeAsync(() => ctx.People.Where(p => p.Email.Contains("substring")).ToListAsync()))
            .Should().Be("translated, zero rows");
        (await DescribeAsync(() => ctx.People.Where(p => p.Email.StartsWith("substring")).ToListAsync()))
            .Should().Be("translated, zero rows");
    }

    private static async Task<string> DescribeAsync(Func<Task<List<Person>>> query)
    {
        try
        {
            var rows = await query().ConfigureAwait(false);
            return rows.Count == 0 ? "translated, zero rows" : $"MATCHED {rows.Count}";
        }
        catch (InvalidOperationException)
        {
            return "untranslatable";
        }
    }
}
