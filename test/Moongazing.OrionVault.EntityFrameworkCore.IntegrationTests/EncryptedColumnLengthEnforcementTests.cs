namespace Moongazing.OrionVault.EntityFrameworkCore.IntegrationTests;

using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;
using MySqlConnector;
using Testcontainers.MsSql;
using Testcontainers.MySql;
using Xunit;
using Xunit.Abstractions;

/// <summary>
/// Settles what a LENGTH-ENFORCING store does when an encryption envelope overflows the column the
/// model declared - the question SQLite cannot answer, because it ignores declared column length
/// entirely (see <c>EncryptedColumnBehaviourTests</c>).
/// <para>
/// The answer decides how bad the un-widened <c>MaxLength</c> defect was: an error is a loud, safe
/// failure, whereas a truncation cuts the AES-GCM tag off the end of the envelope and leaves a row
/// that no key can ever decrypt - the plaintext is gone. Both behaviours exist in the wild, so both
/// are pinned here rather than argued about.
/// </para>
/// <para>
/// Also pins the ADO-level mechanism a provider would truncate THROUGH: whether EF Core stamps
/// <see cref="DbParameter.Size"/> from the model's <c>MaxLength</c>.
/// </para>
/// </summary>
public sealed class EncryptedColumnLengthEnforcementTests
{
    private readonly ITestOutputHelper output;

    public EncryptedColumnLengthEnforcementTests(ITestOutputHelper output) => this.output = output;

    private const string Key32B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /// <summary>Fixed AES-GCM envelope overhead: [keyId:2 | nonce:12 | tag:16].</summary>
    private const int EnvelopeOverhead = 30;

    /// <summary>The declared plaintext budget the consumer writes as <c>[MaxLength(64)]</c>.</summary>
    private const int DeclaredMaxLength = 64;

    // ---------------------------------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------------------------------

    /// <summary>A hand-declared narrow binary column: what the model looked like BEFORE the widening fix.</summary>
    public class Narrow
    {
        public int Id { get; set; }

#pragma warning disable CA1819 // Properties should not return arrays - test fixture entity.
        public byte[]? Payload { get; set; }
#pragma warning restore CA1819
    }

    public class NarrowCtx : DbContext
    {
        public NarrowCtx(DbContextOptions opt) : base(opt) { }

        public DbSet<Narrow> Narrows => Set<Narrow>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            ArgumentNullException.ThrowIfNull(modelBuilder);
            // varbinary(64): exactly the column the un-widened configurator produced for a
            // [Encrypted] [MaxLength(64)] property.
            modelBuilder.Entity<Narrow>().Property(n => n.Payload).HasMaxLength(DeclaredMaxLength);
        }
    }

    /// <summary>The same consumer intent, written the normal way, through the real OrionVault wiring.</summary>
    public class Person
    {
        public int Id { get; set; }

        [Encrypted]
        [MaxLength(DeclaredMaxLength)]
        public string Email { get; set; } = null!;
    }

    public class PeopleCtx : DbContext
    {
        public PeopleCtx(DbContextOptions opt) : base(opt) { }

        public DbSet<Person> People => Set<Person>();
    }

    /// <summary>Captures <see cref="DbParameter.Size"/> for every binary parameter EF sends.</summary>
    private sealed class ParameterSizeCapture : DbCommandInterceptor
    {
        public List<(DbType Type, int Size, int ValueLength)> Binary { get; } = [];

        private void Record(DbCommand command)
        {
            foreach (DbParameter p in command.Parameters)
            {
                if (p.Value is byte[] bytes)
                {
                    Binary.Add((p.DbType, p.Size, bytes.Length));
                }
            }
        }

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
    }

    private static async Task<MsSqlContainer> StartSqlServerAsync()
    {
        var container = new MsSqlBuilder().WithImage(ContainerImages.SqlServer).Build();
        await container.StartAsync();
        return container;
    }

    // ---------------------------------------------------------------------------------------
    // SQL Server: the length-enforcing answer.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// SETTLES TRUNCATE-VERSUS-ERROR ON SQL SERVER. A 70-byte envelope written to the
    /// <c>varbinary(64)</c> column the un-widened model declared is REJECTED, not silently cut: SQL
    /// Server raises 8152 ("String or binary data would be truncated") or its 2628 successor, the
    /// transaction rolls back, and no row is written. Loud failure, no data loss - but every insert
    /// of a long value fails in production until the column is widened.
    /// <para>
    /// Also pins the ADO-level mechanism, because it is NOT the one you would guess. EF Core does
    /// stamp <see cref="DbParameter.Size"/> from the model's <c>MaxLength</c> - but only while the
    /// value fits. When the value overflows the facet, EF WIDENS the parameter to the store maximum
    /// (<c>varbinary</c> -> 8000) instead of clamping it, precisely so the parameter never silently
    /// shortens the payload. The whole truncate-versus-error decision is therefore the COLUMN's, and
    /// nothing at the ADO layer protects a store that chooses to truncate.
    /// </para>
    /// </summary>
    [DockerFact]
    public async Task SqlServer_rejects_an_envelope_that_overflows_the_declared_column_length()
    {
        await using var container = await StartSqlServerAsync();

        var capture = new ParameterSizeCapture();
        await using var sp = new ServiceCollection()
            .AddDbContext<NarrowCtx>(o => o
                .UseSqlServer(container.GetConnectionString())
                .AddInterceptors(capture))
            .BuildServiceProvider();

        using var scope = sp.CreateScope();
        var ctx = scope.ServiceProvider.GetRequiredService<NarrowCtx>();
        await ctx.Database.EnsureCreatedAsync();

        // Baseline: a payload that fits. It is the control for the parameter-size claim below.
        var fits = RandomNumberGenerator.GetBytes(DeclaredMaxLength);
        ctx.Narrows.Add(new Narrow { Payload = fits });
        await ctx.SaveChangesAsync();
        ctx.ChangeTracker.Clear();

        capture.Binary.Should().ContainSingle(p => p.ValueLength == fits.Length)
            .Which.Size.Should().Be(
                DeclaredMaxLength,
                "EF Core stamps DbParameter.Size from the model's MaxLength while the value fits");

        // 40 characters of plaintext -> 70 bytes once enveloped: the exact overflow
        // EncryptedColumnBehaviourTests measures on SQLite, where nothing happens.
        var envelope = RandomNumberGenerator.GetBytes(EnvelopeOverhead + 40);
        ctx.Narrows.Add(new Narrow { Payload = envelope });

        var insert = async () => await ctx.SaveChangesAsync();
        var thrown = await insert.Should().ThrowAsync<DbUpdateException>(
            "a length-enforcing store must refuse the write rather than cut the AES-GCM tag off it");

        var sql = thrown.And.InnerException.Should().BeOfType<SqlException>().Subject;
        output.WriteLine($"SQL Server refused the overflowing write with error {sql.Number}: {sql.Message}");
        sql.Number.Should().BeOneOf(
            [8152, 2628],
            "8152 is the classic 'String or binary data would be truncated'; 2628 is its column-naming successor");

        // Only the row that fit is there: the failure is a rejection, not a partial write.
        ctx.ChangeTracker.Clear();
        (await ctx.Narrows.CountAsync()).Should().Be(1);

        capture.Binary.Should().ContainSingle(p => p.ValueLength == envelope.Length)
            .Which.Size.Should().Be(
                8000,
                "EF widens an overflowing parameter to the varbinary maximum rather than clamping it to " +
                "MaxLength, so the parameter cannot truncate and the column alone decides error-versus-truncate");
    }

    /// <summary>
    /// The fix, end to end on the store that enforces length: a <c>[Encrypted] [MaxLength(64)]</c>
    /// string holding 64 characters of MULTI-BYTE text (192 UTF-8 bytes, 222 enveloped) is accepted
    /// and round-trips. Before the widening this insert failed with 8152 on every non-ASCII value
    /// long enough to matter.
    /// </summary>
    [DockerFact]
    public async Task SqlServer_accepts_a_declared_max_length_plaintext_on_an_encrypted_column()
    {
        await using var container = await StartSqlServerAsync();

        await using var sp = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(1, Key32B64));
                o.ActiveKeyId = 1;
            })
            .UseEntityFrameworkCore<PeopleCtx>()
            .Services
            .AddDbContext<PeopleCtx>((s, o) => o.UseSqlServer(container.GetConnectionString()).UseOrionVault(s))
            .BuildServiceProvider();

        using var scope = sp.CreateScope();
        var ctx = scope.ServiceProvider.GetRequiredService<PeopleCtx>();
        await ctx.Database.EnsureCreatedAsync();

        // Worst case the declared facet admits: 64 characters that are 3 UTF-8 bytes each.
        var plaintext = new string('英', DeclaredMaxLength);
        Encoding.UTF8.GetByteCount(plaintext).Should().Be(3 * DeclaredMaxLength, "the fixture must really be worst case");

        ctx.People.Add(new Person { Email = plaintext });
        await ctx.SaveChangesAsync();
        ctx.ChangeTracker.Clear();

        (await ctx.People.SingleAsync()).Email.Should().Be(plaintext);
    }

    // ---------------------------------------------------------------------------------------
    // MySQL: the truncating answer.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// SETTLES TRUNCATE-VERSUS-ERROR ON MYSQL. In strict mode (the 8.x default) MySQL behaves like
    /// SQL Server and refuses the write. With <c>sql_mode</c> cleared - non-strict, still a common
    /// legacy configuration - the same insert SUCCEEDS and silently keeps only the first 64 bytes.
    /// That is the destructive outcome: the AES-GCM tag lives in bytes 14..29 of the envelope and the
    /// ciphertext body runs to the end, so a cut row can never be decrypted with any key. The
    /// plaintext is gone, and only a "Data truncated" warning ever said so.
    /// <para>
    /// Driven over raw ADO rather than an EF provider: the question is the STORE's behaviour, and
    /// this keeps the suite from taking on a third-party EF Core provider to ask it.
    /// </para>
    /// </summary>
    [DockerFact]
    public async Task MySql_in_non_strict_mode_truncates_the_envelope_instead_of_rejecting_it()
    {
        await using var container = new MySqlBuilder().WithImage(ContainerImages.MySql).Build();
        await container.StartAsync();

        await using var connection = new MySqlConnection(container.GetConnectionString());
        await connection.OpenAsync();

        await ExecuteAsync(connection, "SET SESSION sql_mode = '';");
        await ExecuteAsync(connection, "CREATE TABLE narrow (id INT PRIMARY KEY AUTO_INCREMENT, payload VARBINARY(64));");

        var envelope = RandomNumberGenerator.GetBytes(EnvelopeOverhead + 40);

        await using (var insert = connection.CreateCommand())
        {
            insert.CommandText = "INSERT INTO narrow (payload) VALUES (@payload);";
            insert.Parameters.AddWithValue("@payload", envelope);
            (await insert.ExecuteNonQueryAsync()).Should().Be(
                1, "non-strict MySQL accepts the row rather than refusing it");
        }

        await using (var warnings = connection.CreateCommand())
        {
            warnings.CommandText = "SHOW WARNINGS;";
            await using var reader = await warnings.ExecuteReaderAsync();
            var messages = new List<string>();
            while (await reader.ReadAsync())
            {
                messages.Add(reader.GetString(2));
            }

            messages.Should().Contain(m => m.Contains("truncated", StringComparison.OrdinalIgnoreCase),
                "the only signal the store gives is a warning nobody reads");
        }

        await using (var length = connection.CreateCommand())
        {
            length.CommandText = "SELECT LENGTH(payload) FROM narrow;";
            var stored = Convert.ToInt32(await length.ExecuteScalarAsync(), provider: null);
            output.WriteLine($"MySQL (sql_mode='') stored {stored} of {envelope.Length} bytes.");
            stored.Should().Be(
                DeclaredMaxLength,
                "the envelope was cut to the declared width: the GCM tag and the tail of the ciphertext are gone, " +
                "so this row is undecryptable with any key");
        }
    }

    private static async Task ExecuteAsync(MySqlConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
#pragma warning disable CA2100 // Constant SQL from this file only.
        command.CommandText = sql;
#pragma warning restore CA2100
        await command.ExecuteNonQueryAsync();
    }
}
