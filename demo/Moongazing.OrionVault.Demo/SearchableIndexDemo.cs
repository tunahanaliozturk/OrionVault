namespace Moongazing.OrionVault.Demo;

using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;

/// <summary>
/// Demo 6: searchable encrypted columns via an HMAC index, the pattern documented in the
/// README. Because AES-GCM is randomized, you cannot <c>WHERE Email = @p</c>. Instead we
/// store a deterministic HMAC-SHA256 of the normalized value in a separate, non-encrypted
/// <see cref="IndexedCustomer.EmailIndex"/> column and query on the HMAC probe. The HMAC
/// key is distinct from the AES encryption key.
/// </summary>
internal static class SearchableIndexDemo
{
    // Demo-only HMAC key. In production keep this separate from the AES key and load it
    // from a secret store.
    private static readonly byte[] SearchKey = Encoding.UTF8.GetBytes("demo-hmac-search-key-keep-this-separate");

    public static async Task RunAsync()
    {
        DemoConsole.Section(6, "Searchable encrypted column (HMAC index)");

        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();

        await using var provider = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(DemoKeys.KeyIdV1, DemoKeys.KeyV1));
                o.ActiveKeyId = DemoKeys.KeyIdV1;
            })
            .UseEntityFrameworkCore<SearchableDbContext>()
            .Services
            .AddDbContext<SearchableDbContext>((sp, opt) => opt.UseSqlite(connection).UseOrionVault(sp))
            .BuildServiceProvider();

        // --- Seed three customers, each with an HMAC index alongside the encrypted email ---
        using (var scope = provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SearchableDbContext>();
            await db.Database.EnsureCreatedAsync();

            foreach (var email in new[] { "ali@example.com", "veli@example.com", "ayse@example.com" })
            {
                db.Customers.Add(new IndexedCustomer
                {
                    Id = Guid.NewGuid(),
                    Email = email,
                    EmailIndex = ComputeIndex(email)
                });
            }
            await db.SaveChangesAsync();
            DemoConsole.Ok("Seeded 3 customers (encrypted Email + deterministic EmailIndex).");
        }

        // --- Look one up by HMAC probe, then decrypt the matched row ---
        using (var scope = provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SearchableDbContext>();

            const string needle = "veli@example.com";
            byte[] probe = ComputeIndex(needle);
            DemoConsole.Item("Searching for", needle);
            DemoConsole.Item("HMAC probe (base64)", DemoConsole.ShortB64(probe));

            // This WHERE runs server-side against the deterministic index, not the ciphertext.
            var hit = await db.Customers.SingleOrDefaultAsync(c => c.EmailIndex == probe);

            if (hit is not null && hit.Email == needle)
                DemoConsole.Ok($"Matched via HMAC index, decrypted Email = \"{hit.Email}\".");
            else
                DemoConsole.Note("Unexpected: HMAC index lookup did not return the expected row.");

            // A value that was never stored produces no match.
            var miss = await db.Customers.SingleOrDefaultAsync(c => c.EmailIndex == ComputeIndex("nobody@example.com"));
            DemoConsole.Item("Lookup for unknown email", miss is null ? "no match (correct)" : "unexpected match");
        }
    }

    private static byte[] ComputeIndex(string email)
        => HMACSHA256.HashData(SearchKey, Encoding.UTF8.GetBytes(email.ToLowerInvariant()));
}

/// <summary>Customer with an encrypted email and a deterministic HMAC search index.</summary>
public class IndexedCustomer
{
    public Guid Id { get; set; }

    [Moongazing.OrionVault.EntityFrameworkCore.Encrypted]
    public string Email { get; set; } = null!;

    // Deterministic HMAC of Email. Searchable, irreversible, length-stable. NOT encrypted.
    public byte[] EmailIndex { get; set; } = null!;
}

/// <summary>DbContext for the searchable-index demo.</summary>
public class SearchableDbContext : DbContext
{
    public SearchableDbContext(DbContextOptions<SearchableDbContext> options) : base(options) { }

    public DbSet<IndexedCustomer> Customers => Set<IndexedCustomer>();
}
