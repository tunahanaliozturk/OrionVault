namespace Moongazing.OrionVault.Demo;

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;

/// <summary>
/// Demo 7: searchable encryption via the built-in blind index (v0.3). This replaces the
/// hand-rolled HMAC of demo 6 with the first-class <see cref="IBlindIndexProvider"/>. You
/// opt in with <c>UseBlindIndex</c>, resolve the provider from DI, store
/// <c>provider.Compute(value).Bytes</c> in a plain (non-encrypted) column alongside the
/// AES-GCM ciphertext, and query that column with an equality probe. The randomized
/// ciphertext stays non-deterministic; only the deterministic index is searchable.
/// <para>
/// The provider normalizes before hashing (default: trim + invariant-lowercase), so callers
/// do not lowercase by hand, and its keys are versioned. The second half of the demo rotates
/// the index key and uses <c>ComputeAllVersions</c> to build an OR-probe that still matches
/// rows indexed under the retired key before a re-index sweep runs.
/// </para>
/// </summary>
internal static class BlindIndexDemo
{
    public static async Task RunAsync()
    {
        DemoConsole.Section(7, "Searchable encryption via the built-in blind index (v0.3)");

        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();

        // --- Host A: encryption key 1, blind index version 1 active. ---
        await using var providerV1 = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(DemoKeys.KeyIdV1, DemoKeys.KeyV1));
                o.ActiveKeyId = DemoKeys.KeyIdV1;

                // Opt in to searchable encryption. Index keys are independent from the AES keys.
                o.UseBlindIndex(b => b.Add(DemoKeys.BlindIndexVersionV1, DemoKeys.BlindIndexKeyV1));
                o.ActiveBlindIndexVersion = DemoKeys.BlindIndexVersionV1;
            })
            .UseEntityFrameworkCore<BlindIndexDbContext>()
            .Services
            .AddDbContext<BlindIndexDbContext>((sp, opt) => opt.UseSqlite(connection).UseOrionVault(sp))
            .BuildServiceProvider();

        // --- Seed three customers. The index column is populated from the provider. ---
        using (var scope = providerV1.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<BlindIndexDbContext>();
            var index = scope.ServiceProvider.GetRequiredService<IBlindIndexProvider>();
            await db.Database.EnsureCreatedAsync();

            // Mixed case and surrounding whitespace on purpose: the provider's default
            // normalization (trim + invariant-lowercase) folds these to the same index.
            foreach (var email in new[] { "  Ali@Example.com ", "veli@example.com", "ayse@example.com" })
            {
                db.Customers.Add(new IndexedAccount
                {
                    Id = Guid.NewGuid(),
                    Email = email.Trim(),
                    EmailIndex = index.Compute(email).Bytes
                });
            }

            await db.SaveChangesAsync();
            DemoConsole.Ok("Seeded 3 accounts (encrypted Email + deterministic blind index).");
        }

        // --- Look one up by equality probe, then decrypt the matched row. ---
        using (var scope = providerV1.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<BlindIndexDbContext>();
            var index = scope.ServiceProvider.GetRequiredService<IBlindIndexProvider>();

            // Different casing than was stored; normalization makes it match anyway.
            const string needle = "ALI@example.com";
            byte[] probe = index.Compute(needle).Bytes;
            DemoConsole.Item("Searching for", needle);
            DemoConsole.Item("Index probe (base64)", DemoConsole.ShortB64(probe));

            // Equality runs server-side against the deterministic index, not the ciphertext.
            var hit = await db.Customers.SingleOrDefaultAsync(c => c.EmailIndex == probe);

            if (hit is not null && hit.Email == "Ali@Example.com")
                DemoConsole.Ok($"Matched via blind index, decrypted Email = \"{hit.Email}\".");
            else
                DemoConsole.Note("Unexpected: blind index lookup did not return the expected row.");

            // Matches verifies a candidate against a stored index, resolving the key version
            // from the stored bytes. A never-stored value produces no match.
            byte[] stored = hit!.EmailIndex;
            DemoConsole.Item("Matches stored index", index.Matches(needle, stored) ? "yes (correct)" : "no");
            DemoConsole.Item("Matches wrong value", index.Matches("nobody@example.com", stored) ? "yes" : "no (correct)");
        }

        // --- Rotate the index key. Host B registers version 1 (retained) AND version 2 ---
        // --- (active). ComputeAllVersions lets search keep working before a re-index sweep. ---
        await using var providerV2 = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(DemoKeys.KeyIdV1, DemoKeys.KeyV1));
                o.ActiveKeyId = DemoKeys.KeyIdV1;

                o.UseBlindIndex(b =>
                {
                    b.Add(DemoKeys.BlindIndexVersionV1, DemoKeys.BlindIndexKeyV1); // keep so old rows still match
                    b.Add(DemoKeys.BlindIndexVersionV2, DemoKeys.BlindIndexKeyV2); // new key for new writes
                });
                o.ActiveBlindIndexVersion = DemoKeys.BlindIndexVersionV2;
            })
            .UseEntityFrameworkCore<BlindIndexDbContext>()
            .Services
            .AddDbContext<BlindIndexDbContext>((sp, opt) => opt.UseSqlite(connection).UseOrionVault(sp))
            .BuildServiceProvider();

        using (var scope = providerV2.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<BlindIndexDbContext>();
            var index = scope.ServiceProvider.GetRequiredService<IBlindIndexProvider>();

            // The three seeded rows still carry version-1 indexes. A probe under the new active
            // version alone would miss them, so probe under every retained version and OR the
            // equality checks together. ComputeAllVersions returns newest-first; here that is
            // [v2, v1]. The seeded rows match on the v1 probe.
            const string needle = "veli@example.com";
            var allVersions = index.ComputeAllVersions(needle);
            byte[] probeV2 = allVersions[0].Bytes;
            byte[] probeV1 = allVersions[1].Bytes;
            DemoConsole.Item("Active index version", index.ActiveVersion.ToString(System.Globalization.CultureInfo.InvariantCulture));
            DemoConsole.Item("OR-probe versions", string.Join(", ", allVersions.Select(r => r.Version)));

            // Explicit equality ORs translate to SQL; an array Contains over byte[] does not.
            var hit = await db.Customers
                .SingleOrDefaultAsync(c => c.EmailIndex == probeV2 || c.EmailIndex == probeV1);

            if (hit is not null && hit.Email == needle)
                DemoConsole.Ok("OR-probe across versions matched the row still on the retired key.");
            else
                DemoConsole.Note("Unexpected: cross-version probe did not return the expected row.");
        }
    }
}

/// <summary>Account with an encrypted email and a deterministic blind index column.</summary>
public class IndexedAccount
{
    public Guid Id { get; set; }

    [Moongazing.OrionVault.EntityFrameworkCore.Encrypted]
    public string Email { get; set; } = null!;

    // The blind index token from IBlindIndexProvider.Compute(...).Bytes. Searchable,
    // irreversible, self-describing (carries its key version). NOT encrypted.
    public byte[] EmailIndex { get; set; } = null!;
}

/// <summary>DbContext for the blind-index demo.</summary>
public class BlindIndexDbContext : DbContext
{
    public BlindIndexDbContext(DbContextOptions<BlindIndexDbContext> options) : base(options) { }

    public DbSet<IndexedAccount> Customers => Set<IndexedAccount>();
}
