namespace Moongazing.OrionVault.EntityFrameworkCore.Tests;

using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore.Maintenance;
using Moongazing.OrionVault.Rotation;
using Xunit;

/// <summary>
/// End-to-end coverage for the v0.3.4 EF Core re-encryption / blind-index re-index runner over a
/// real SQLite database. Each test seeds rows under an OLD key (and OLD blind-index version) via
/// the normal encrypting context, then runs the tool from a SECOND host whose ACTIVE key /
/// version is newer and which maps the same table as RAW bytes, and asserts the migration.
/// </summary>
public sealed class ReencryptionRunnerTests : IDisposable
{
    // Two distinct 32-byte AES keys, base64. Key 1 is the original write key, key 2 the rotated one.
    private const string Key1B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    private static readonly string Key2B64 = Convert.ToBase64String(MakeKey(0x22));

    // Two distinct 32-byte blind-index keys, base64. Independent from the AES keys.
    private static readonly string IndexKey1B64 = Convert.ToBase64String(MakeKey(0x31));
    private static readonly string IndexKey2B64 = Convert.ToBase64String(MakeKey(0x32));

    private readonly SqliteConnection _conn;

    public ReencryptionRunnerTests()
    {
        // A uniquely-named shared-cache in-memory DB kept alive by this open connection, so the
        // encrypting context and the raw maintenance context address the same table while staying
        // fully isolated from other test instances (a fixed name would leak rows across tests).
        var dbName = "reencrypt-" + Guid.NewGuid().ToString("N");
        _conn = new SqliteConnection($"DataSource={dbName};Mode=Memory;Cache=Shared");
        _conn.Open();
    }

    public void Dispose() => _conn.Dispose();

    private static byte[] MakeKey(byte seed)
    {
        var k = new byte[32];
        Array.Fill(k, seed);
        return k;
    }

    // ----- Encrypting model: columns flow through the OrionVault value converter on this context.

    public class Customer
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = null!;
        [Encrypted] public string Email { get; set; } = null!;
        // Blind index over Email. Plain byte[] column (not encrypted), populated by the caller.
#pragma warning disable CA1819
        public byte[] EmailIndex { get; set; } = null!;
        [Encrypted] public byte[]? IdScan { get; set; }
#pragma warning restore CA1819
    }

    public class EncryptingCtx : DbContext
    {
        public EncryptingCtx(DbContextOptions opt) : base(opt) { }
        public DbSet<Customer> Customers => Set<Customer>();
    }

    // ----- Raw model: same "Customers" table, but the encrypted columns are plain byte[] so the
    // maintenance pass sees the on-disk AES-GCM envelope rather than the decrypted value.

    public class RawCustomer
    {
#pragma warning disable CA1819
        public Guid Id { get; set; }
        public string Name { get; set; } = null!;
        public byte[]? Email { get; set; }
        public byte[]? EmailIndex { get; set; }
        public byte[]? IdScan { get; set; }
#pragma warning restore CA1819
    }

    public class RawCtx : DbContext
    {
        public RawCtx(DbContextOptions opt) : base(opt) { }
        public DbSet<RawCustomer> Customers => Set<RawCustomer>();
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            ArgumentNullException.ThrowIfNull(modelBuilder);
            modelBuilder.Entity<RawCustomer>().ToTable("Customers");
        }
    }

    // Builds an encrypting host. IMPORTANT: a single test must build at most ONE encrypting host
    // for a given EncryptingCtx, because EF Core's default IModelCacheKeyFactory keys the compiled
    // model on the context CLR type only - two encrypting hosts with different active keys over the
    // same type would share converters bound to whichever host compiled the model first. Tests that
    // need rows already on the active key seed them with SeedRawAsync instead (raw envelope insert).
    private ServiceProvider BuildEncryptingHost(short activeKeyId, bool withBlindIndex, short activeIndexVersion)
        => new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k =>
                {
                    k.Add(1, Key1B64);
                    k.Add(2, Key2B64);
                });
                o.ActiveKeyId = activeKeyId;
                if (withBlindIndex)
                {
                    o.UseBlindIndex(b =>
                    {
                        b.Add(1, IndexKey1B64);
                        b.Add(2, IndexKey2B64);
                    });
                    o.ActiveBlindIndexVersion = activeIndexVersion;
                }
            })
            .UseEntityFrameworkCore<EncryptingCtx>()
            .Services
            .AddDbContext<EncryptingCtx>((sp, o) => o.UseSqlite(_conn).UseOrionVault(sp))
            .BuildServiceProvider();

    // Host used to RUN the tool: active key 2 (and optionally active index version 2). Registers
    // the runner and a raw DbContext over the same connection.
    private ServiceProvider BuildMaintenanceHost(bool withBlindIndex)
        => new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k =>
                {
                    k.Add(1, Key1B64);
                    k.Add(2, Key2B64);
                });
                o.ActiveKeyId = 2;
                if (withBlindIndex)
                {
                    o.UseBlindIndex(b =>
                    {
                        b.Add(1, IndexKey1B64);
                        b.Add(2, IndexKey2B64);
                    });
                    o.ActiveBlindIndexVersion = 2;
                }
            })
            .UseReencryptionRunner()
            .Services
            .AddDbContext<RawCtx>(o => o.UseSqlite(_conn))
            .BuildServiceProvider();

    private static ReencryptionPlan<RawCustomer> EmailPlan(bool withBlindIndex)
    {
        var plan = ReencryptionPlan.For<RawCustomer>(q => q.OrderBy(c => c.Id));
        if (withBlindIndex)
        {
            plan.WithColumn(EncryptedColumnPlan.ForStringWithBlindIndex<RawCustomer>(
                nameof(RawCustomer.Email),
                c => c.Email,
                (c, v) => c.Email = v,
                c => c.EmailIndex,
                (c, v) => c.EmailIndex = v));
        }
        else
        {
            plan.WithColumn(EncryptedColumnPlan.ForString<RawCustomer>(
                nameof(RawCustomer.Email),
                c => c.Email,
                (c, v) => c.Email = v));
        }

        return plan;
    }

    private async Task SeedAsync(short activeKeyId, bool withBlindIndex, short activeIndexVersion, params string[] emails)
    {
        await using var sp = BuildEncryptingHost(activeKeyId, withBlindIndex, activeIndexVersion);
        using var scope = sp.CreateScope();
        var ctx = scope.ServiceProvider.GetRequiredService<EncryptingCtx>();
        await ctx.Database.EnsureCreatedAsync();

        IBlindIndexProvider? index = withBlindIndex
            ? scope.ServiceProvider.GetRequiredService<IBlindIndexProvider>()
            : null;

        foreach (var email in emails)
        {
            ctx.Customers.Add(new Customer
            {
                Id = Guid.NewGuid(),
                Name = "n",
                Email = email,
                EmailIndex = index?.Compute(email).Bytes ?? [],
            });
        }

        await ctx.SaveChangesAsync();
    }

    // Seeds rows whose stored envelope and blind-index token are produced by the MAINTENANCE host's
    // own IEncryptor / IBlindIndexProvider (active key 2, active index version 2), inserted via the
    // raw context. Used to create rows that are ALREADY on the active key/version without standing up
    // a second encrypting host (which would collide with the first host's EF model cache).
    private static async Task SeedRawAsync(ServiceProvider maintenanceHost, bool withBlindIndex, params string[] emails)
    {
        using var scope = maintenanceHost.CreateScope();
        var raw = scope.ServiceProvider.GetRequiredService<RawCtx>();
        var encryptor = scope.ServiceProvider.GetRequiredService<IEncryptor>();
        IBlindIndexProvider? index = withBlindIndex
            ? scope.ServiceProvider.GetRequiredService<IBlindIndexProvider>()
            : null;
        await raw.Database.EnsureCreatedAsync();

        foreach (var email in emails)
        {
            raw.Customers.Add(new RawCustomer
            {
                Id = Guid.NewGuid(),
                Name = "n",
                Email = encryptor.EncryptString(email),
                EmailIndex = index?.Compute(email).Bytes ?? [],
                IdScan = null,
            });
        }

        await raw.SaveChangesAsync();
    }

    [Fact]
    public async Task Old_key_rows_become_readable_under_the_active_key_after_a_pass()
    {
        await SeedAsync(activeKeyId: 1, withBlindIndex: false, activeIndexVersion: 0, "ali@example.com", "veli@example.com");

        // Sanity: rows are on key id 1 before the pass (raw header first 2 bytes == 0x00 0x01).
        await using (var rawSp = BuildMaintenanceHost(withBlindIndex: false))
        {
            using var rawScope = rawSp.CreateScope();
            var raw = rawScope.ServiceProvider.GetRequiredService<RawCtx>();
            var before = await raw.Customers.OrderBy(c => c.Id).ToListAsync();
            before.Should().OnlyContain(c => c.Email!.Length >= 2 && c.Email![0] == 0 && c.Email![1] == 1);
        }

        // Run the tool from the host whose active key is 2.
        await using var sp = BuildMaintenanceHost(withBlindIndex: false);
        ReencryptionReport report;
        using (var scope = sp.CreateScope())
        {
            var runner = scope.ServiceProvider.GetRequiredService<IEncryptionMaintenance>();
            var ctx = scope.ServiceProvider.GetRequiredService<RawCtx>();
            report = await runner.RunAsync(ctx, EmailPlan(withBlindIndex: false));
        }

        report.Scanned.Should().Be(2);
        report.ReEncrypted.Should().Be(2);
        report.Skipped.Should().Be(0);
        report.Errors.Should().Be(0);

        // Rows now decrypt under the active key (2) through a fresh encrypting host whose active id is 2.
        await using var verifySp = BuildEncryptingHost(activeKeyId: 2, withBlindIndex: false, activeIndexVersion: 0);
        using var verifyScope = verifySp.CreateScope();
        var verifyCtx = verifyScope.ServiceProvider.GetRequiredService<EncryptingCtx>();
        var emails = await verifyCtx.Customers.OrderBy(c => c.Name).Select(c => c.Email).ToListAsync();
        emails.Should().BeEquivalentTo(["ali@example.com", "veli@example.com"]);

        // And the raw header now reads key id 2.
        using var afterScope = sp.CreateScope();
        var afterRaw = afterScope.ServiceProvider.GetRequiredService<RawCtx>();
        var after = await afterRaw.Customers.ToListAsync();
        after.Should().OnlyContain(c => c.Email![0] == 0 && c.Email![1] == 2);
    }

    [Fact]
    public async Task Blind_index_lookups_match_under_the_active_version_after_re_index()
    {
        await SeedAsync(activeKeyId: 1, withBlindIndex: true, activeIndexVersion: 1, "ALI@example.com", "veli@example.com");

        await using var sp = BuildMaintenanceHost(withBlindIndex: true);
        ReencryptionReport report;
        using (var scope = sp.CreateScope())
        {
            var runner = scope.ServiceProvider.GetRequiredService<IEncryptionMaintenance>();
            var ctx = scope.ServiceProvider.GetRequiredService<RawCtx>();
            report = await runner.RunAsync(ctx, EmailPlan(withBlindIndex: true));
        }

        report.ReEncrypted.Should().Be(2);
        report.ReIndexed.Should().Be(2);
        report.Errors.Should().Be(0);

        // Every stored index token now carries the active version (2) in its 2-byte prefix.
        using (var afterScope = sp.CreateScope())
        {
            var afterRaw = afterScope.ServiceProvider.GetRequiredService<RawCtx>();
            var indexes = await afterRaw.Customers.Select(c => c.EmailIndex).ToListAsync();
            indexes.Should().OnlyContain(i => i![0] == 0 && i![1] == 2);
        }

        // A probe computed under the active version now matches the re-indexed row with a single
        // (current-version) equality predicate, which is the whole point of the re-index sweep.
        await using var verifySp = BuildEncryptingHost(activeKeyId: 2, withBlindIndex: true, activeIndexVersion: 2);
        using var verifyScope = verifySp.CreateScope();
        var index = verifyScope.ServiceProvider.GetRequiredService<IBlindIndexProvider>();
        var verifyCtx = verifyScope.ServiceProvider.GetRequiredService<EncryptingCtx>();

        index.ActiveVersion.Should().Be(2);
        byte[] probe = index.Compute("ali@EXAMPLE.com").Bytes; // different casing: normalization folds it
        probe[1].Should().Be(2);

        var hit = await verifyCtx.Customers.SingleOrDefaultAsync(c => c.EmailIndex == probe);
        hit.Should().NotBeNull();
        hit!.Email.Should().Be("ALI@example.com");
    }

    [Fact]
    public async Task Re_running_an_already_migrated_table_is_a_no_op()
    {
        await SeedAsync(activeKeyId: 1, withBlindIndex: true, activeIndexVersion: 1, "a@x.com", "b@x.com", "c@x.com");

        await using var sp = BuildMaintenanceHost(withBlindIndex: true);

        // First pass migrates everything.
        ReencryptionReport first;
        using (var scope = sp.CreateScope())
        {
            var runner = scope.ServiceProvider.GetRequiredService<IEncryptionMaintenance>();
            var ctx = scope.ServiceProvider.GetRequiredService<RawCtx>();
            first = await runner.RunAsync(ctx, EmailPlan(withBlindIndex: true));
        }

        first.ReEncrypted.Should().Be(3);
        first.ReIndexed.Should().Be(3);

        // Capture the exact stored bytes after the first pass.
        Dictionary<Guid, (byte[] Email, byte[] Index)> afterFirst;
        using (var scope = sp.CreateScope())
        {
            var raw = scope.ServiceProvider.GetRequiredService<RawCtx>();
            afterFirst = await raw.Customers.ToDictionaryAsync(c => c.Id, c => (c.Email!, c.EmailIndex!));
        }

        // Second pass must touch nothing.
        ReencryptionReport second;
        using (var scope = sp.CreateScope())
        {
            var runner = scope.ServiceProvider.GetRequiredService<IEncryptionMaintenance>();
            var ctx = scope.ServiceProvider.GetRequiredService<RawCtx>();
            second = await runner.RunAsync(ctx, EmailPlan(withBlindIndex: true));
        }

        second.Scanned.Should().Be(3);
        second.ReEncrypted.Should().Be(0);
        second.ReIndexed.Should().Be(0);
        second.Skipped.Should().Be(3);
        second.Errors.Should().Be(0);

        // Bytes are byte-for-byte identical: the no-op pass did not rewrite a single envelope or token.
        using (var scope = sp.CreateScope())
        {
            var raw = scope.ServiceProvider.GetRequiredService<RawCtx>();
            var afterSecond = await raw.Customers.ToDictionaryAsync(c => c.Id, c => (c.Email!, c.EmailIndex!));
            foreach (var (id, before) in afterFirst)
            {
                afterSecond[id].Item1.Should().Equal(before.Email);
                afterSecond[id].Item2.Should().Equal(before.Index);
            }
        }
    }

    [Fact]
    public async Task An_interrupted_pass_resumes_correctly_on_re_run()
    {
        await SeedAsync(activeKeyId: 1, withBlindIndex: true, activeIndexVersion: 1,
            "r1@x.com", "r2@x.com", "r3@x.com", "r4@x.com", "r5@x.com");

        await using var sp = BuildMaintenanceHost(withBlindIndex: true);

        // Simulate an interruption: cancel after the first batch (size 2) has been saved. With 5
        // rows and BatchSize 2, the first batch persists 2 rows, then cancellation fires before the
        // remaining rows are processed.
        using var cts = new CancellationTokenSource();
        var plan = EmailPlan(withBlindIndex: true).WithBatchSize(2);

        using (var scope = sp.CreateScope())
        {
            var ctx = scope.ServiceProvider.GetRequiredService<RawCtx>();
            // Cancel the token as soon as the first batch is committed: hook SavedChanges.
            ctx.SavedChanges += (_, _) => cts.Cancel();
            var runner = scope.ServiceProvider.GetRequiredService<IEncryptionMaintenance>();

            var act = async () => await runner.RunAsync(ctx, plan, cts.Token);
            await act.Should().ThrowAsync<OperationCanceledException>();
        }

        // After the interruption, a strict subset of rows is migrated to key 2; at least the first
        // batch (2 rows) and not all 5.
        int migratedAfterInterrupt;
        using (var scope = sp.CreateScope())
        {
            var raw = scope.ServiceProvider.GetRequiredService<RawCtx>();
            var rows = await raw.Customers.ToListAsync();
            migratedAfterInterrupt = rows.Count(c => c.Email![1] == 2);
            migratedAfterInterrupt.Should().BeInRange(2, 4);
        }

        // Resume: a fresh, uncancelled pass finishes the remainder. It re-scans all 5 but no-ops the
        // already-migrated prefix, so ReEncrypted equals only the rows still on key 1.
        ReencryptionReport resume;
        using (var scope = sp.CreateScope())
        {
            var runner = scope.ServiceProvider.GetRequiredService<IEncryptionMaintenance>();
            var ctx = scope.ServiceProvider.GetRequiredService<RawCtx>();
            resume = await runner.RunAsync(ctx, EmailPlan(withBlindIndex: true).WithBatchSize(2));
        }

        resume.Scanned.Should().Be(5);
        resume.ReEncrypted.Should().Be(5 - migratedAfterInterrupt);
        resume.Skipped.Should().Be(migratedAfterInterrupt);
        resume.Errors.Should().Be(0);

        // All five rows are now on key 2 and index version 2, and all decrypt + match.
        await using var verifySp = BuildEncryptingHost(activeKeyId: 2, withBlindIndex: true, activeIndexVersion: 2);
        using var verifyScope = verifySp.CreateScope();
        var verifyCtx = verifyScope.ServiceProvider.GetRequiredService<EncryptingCtx>();
        var index = verifyScope.ServiceProvider.GetRequiredService<IBlindIndexProvider>();
        var all = await verifyCtx.Customers.ToListAsync();
        all.Should().HaveCount(5);
        foreach (var c in all)
        {
            index.Matches(c.Email, c.EmailIndex).Should().BeTrue();
        }
    }

    [Fact]
    public async Task A_row_already_on_the_active_key_is_skipped_not_rewritten()
    {
        await using var sp = BuildMaintenanceHost(withBlindIndex: false);

        // Two rows on key 1 (need rotation) ...
        await SeedAsync(activeKeyId: 1, withBlindIndex: false, activeIndexVersion: 0, "old1@x.com", "old2@x.com");
        // ... and one row already on the active key 2 (must be skipped).
        await SeedRawAsync(sp, withBlindIndex: false, "new@x.com");

        ReencryptionReport report;
        using (var scope = sp.CreateScope())
        {
            var runner = scope.ServiceProvider.GetRequiredService<IEncryptionMaintenance>();
            var ctx = scope.ServiceProvider.GetRequiredService<RawCtx>();
            report = await runner.RunAsync(ctx, EmailPlan(withBlindIndex: false));
        }

        report.Scanned.Should().Be(3);
        report.ReEncrypted.Should().Be(2);
        report.Skipped.Should().Be(1);
    }

    [Fact]
    public async Task Byte_array_columns_are_rotated_too()
    {
        // Seed one row on key 1 with both an encrypted string and an encrypted byte[] column.
        await using (var seedSp = BuildEncryptingHost(activeKeyId: 1, withBlindIndex: false, activeIndexVersion: 0))
        {
            using var scope = seedSp.CreateScope();
            var ctx = scope.ServiceProvider.GetRequiredService<EncryptingCtx>();
            await ctx.Database.EnsureCreatedAsync();
            ctx.Customers.Add(new Customer
            {
                Id = Guid.NewGuid(),
                Name = "n",
                Email = "e@x.com",
                EmailIndex = [],
                IdScan = [9, 8, 7, 6, 5],
            });
            await ctx.SaveChangesAsync();
        }

        await using var sp = BuildMaintenanceHost(withBlindIndex: false);
        var plan = ReencryptionPlan.For<RawCustomer>(q => q.OrderBy(c => c.Id))
            .WithColumn(EncryptedColumnPlan.ForString<RawCustomer>(
                nameof(RawCustomer.Email), c => c.Email, (c, v) => c.Email = v))
            .WithColumn(EncryptedColumnPlan.ForBytes<RawCustomer>(
                nameof(RawCustomer.IdScan), c => c.IdScan, (c, v) => c.IdScan = v));

        ReencryptionReport report;
        using (var scope = sp.CreateScope())
        {
            var runner = scope.ServiceProvider.GetRequiredService<IEncryptionMaintenance>();
            var ctx = scope.ServiceProvider.GetRequiredService<RawCtx>();
            report = await runner.RunAsync(ctx, plan);
        }

        // One row, re-encrypted once (the row-level flag is set because at least one column rotated).
        report.Scanned.Should().Be(1);
        report.ReEncrypted.Should().Be(1);

        await using var verifySp = BuildEncryptingHost(activeKeyId: 2, withBlindIndex: false, activeIndexVersion: 0);
        using var verifyScope = verifySp.CreateScope();
        var verifyCtx = verifyScope.ServiceProvider.GetRequiredService<EncryptingCtx>();
        var loaded = await verifyCtx.Customers.SingleAsync();
        loaded.Email.Should().Be("e@x.com");
        loaded.IdScan.Should().Equal([9, 8, 7, 6, 5]);
    }

    [Fact]
    public async Task A_null_encrypted_column_is_left_untouched()
    {
        await using (var seedSp = BuildEncryptingHost(activeKeyId: 1, withBlindIndex: false, activeIndexVersion: 0))
        {
            using var scope = seedSp.CreateScope();
            var ctx = scope.ServiceProvider.GetRequiredService<EncryptingCtx>();
            await ctx.Database.EnsureCreatedAsync();
            // IdScan null; Email present and on key 1.
            ctx.Customers.Add(new Customer { Id = Guid.NewGuid(), Name = "n", Email = "e@x.com", EmailIndex = [], IdScan = null });
            await ctx.SaveChangesAsync();
        }

        await using var sp = BuildMaintenanceHost(withBlindIndex: false);
        var plan = ReencryptionPlan.For<RawCustomer>(q => q.OrderBy(c => c.Id))
            .WithColumn(EncryptedColumnPlan.ForBytes<RawCustomer>(
                nameof(RawCustomer.IdScan), c => c.IdScan, (c, v) => c.IdScan = v));

        ReencryptionReport report;
        using (var scope = sp.CreateScope())
        {
            var runner = scope.ServiceProvider.GetRequiredService<IEncryptionMaintenance>();
            var ctx = scope.ServiceProvider.GetRequiredService<RawCtx>();
            report = await runner.RunAsync(ctx, plan);
        }

        // The only column considered (IdScan) is null, so the row needs nothing: skipped, not an error.
        report.Scanned.Should().Be(1);
        report.ReEncrypted.Should().Be(0);
        report.Skipped.Should().Be(1);
        report.Errors.Should().Be(0);
    }

    [Fact]
    public async Task A_blind_index_plan_without_a_registered_provider_throws()
    {
        await SeedAsync(activeKeyId: 1, withBlindIndex: false, activeIndexVersion: 0, "e@x.com");

        // Maintenance host WITHOUT UseBlindIndex, but the plan asks for a blind-index column.
        await using var sp = BuildMaintenanceHost(withBlindIndex: false);
        using var scope = sp.CreateScope();
        var runner = scope.ServiceProvider.GetRequiredService<IEncryptionMaintenance>();
        var ctx = scope.ServiceProvider.GetRequiredService<RawCtx>();

        var act = async () => await runner.RunAsync(ctx, EmailPlan(withBlindIndex: true));
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*IBlindIndexProvider*");
    }

    [Fact]
    public async Task A_plan_with_no_columns_throws()
    {
        await using var sp = BuildMaintenanceHost(withBlindIndex: false);
        using var scope = sp.CreateScope();
        var runner = scope.ServiceProvider.GetRequiredService<IEncryptionMaintenance>();
        var ctx = scope.ServiceProvider.GetRequiredService<RawCtx>();
        await ctx.Database.EnsureCreatedAsync();

        var emptyPlan = ReencryptionPlan.For<RawCustomer>(q => q.OrderBy(c => c.Id));
        var act = async () => await runner.RunAsync(ctx, emptyPlan);
        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*no columns*");
    }

    [Fact]
    public async Task A_stale_blind_index_is_recomputed_even_when_the_ciphertext_is_already_active()
    {
        // Edge case: a row whose AES ciphertext is ALREADY on the active key (2) but whose blind
        // index is still on the OLD version (1). Only the index must be rewritten. Seed it directly
        // through the maintenance host so the envelope is key-2 while the index token is forced to
        // version 1 via ComputeForVersion.
        await using var sp = BuildMaintenanceHost(withBlindIndex: true); // active key 2, active index version 2
        using (var seedScope = sp.CreateScope())
        {
            var raw = seedScope.ServiceProvider.GetRequiredService<RawCtx>();
            var encryptor = seedScope.ServiceProvider.GetRequiredService<IEncryptor>();
            var seedIndex = seedScope.ServiceProvider.GetRequiredService<IBlindIndexProvider>();
            await raw.Database.EnsureCreatedAsync();
            raw.Customers.Add(new RawCustomer
            {
                Id = Guid.NewGuid(),
                Name = "n",
                Email = encryptor.EncryptString("edge@x.com"),       // key 2 (active)
                EmailIndex = seedIndex.ComputeForVersion("edge@x.com", 1).Bytes, // version 1 (stale)
                IdScan = null,
            });
            await raw.SaveChangesAsync();
        }

        ReencryptionReport report;
        using (var scope = sp.CreateScope())
        {
            var runner = scope.ServiceProvider.GetRequiredService<IEncryptionMaintenance>();
            var ctx = scope.ServiceProvider.GetRequiredService<RawCtx>();
            report = await runner.RunAsync(ctx, EmailPlan(withBlindIndex: true));
        }

        report.Scanned.Should().Be(1);
        report.ReEncrypted.Should().Be(0); // ciphertext already active
        report.ReIndexed.Should().Be(1);   // index was stale
        report.Skipped.Should().Be(0);
        report.Errors.Should().Be(0);

        await using var verifySp = BuildEncryptingHost(activeKeyId: 2, withBlindIndex: true, activeIndexVersion: 2);
        using var verifyScope = verifySp.CreateScope();
        var index = verifyScope.ServiceProvider.GetRequiredService<IBlindIndexProvider>();
        var verifyCtx = verifyScope.ServiceProvider.GetRequiredService<EncryptingCtx>();
        byte[] probe = index.Compute("edge@x.com").Bytes;
        var hit = await verifyCtx.Customers.SingleOrDefaultAsync(c => c.EmailIndex == probe);
        hit.Should().NotBeNull();
    }
}
