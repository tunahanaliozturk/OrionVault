namespace Moongazing.OrionVault.Demo;

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;

/// <summary>
/// Demo 5: the EF Core integration end to end against a SQLite in-memory database.
/// We write a <see cref="Customer"/>, read the raw column bytes back with a SQL query to
/// prove they are ciphertext on disk, then materialize the entity through EF Core to show
/// the value converter transparently decrypts the columns.
/// </summary>
internal static class EfCoreColumnEncryptionDemo
{
    public static async Task RunAsync()
    {
        DemoConsole.Section(5, "EF Core column encryption (SQLite in-memory)");

        // A shared, OPEN connection keeps the in-memory database alive for the whole demo.
        // Closing the last connection to "Data Source=:memory:" drops the schema and data.
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();

        await using var provider = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(DemoKeys.KeyIdV1, DemoKeys.KeyV1));
                o.ActiveKeyId = DemoKeys.KeyIdV1;
            })
            .UseEntityFrameworkCore<DemoDbContext>()
            .Services
            .AddDbContext<DemoDbContext>((sp, opt) => opt.UseSqlite(connection).UseOrionVault(sp))
            .BuildServiceProvider();

        var customerId = Guid.NewGuid();

        // --- Write path ---
        using (var scope = provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<DemoDbContext>();
            await db.Database.EnsureCreatedAsync();

            db.Customers.Add(new Customer
            {
                Id = customerId,
                FullName = "Ali Veli",
                Email = "ali.veli@example.com",
                NationalId = "12345678901"
            });
            await db.SaveChangesAsync();
            DemoConsole.Ok("Saved one Customer (Email + NationalId are [Encrypted]).");
        }

        // --- Inspect the raw bytes actually stored on disk ---
        using (var scope = provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<DemoDbContext>();

            byte[] rawEmail = await db.Database
                .SqlQuery<byte[]>($"SELECT Email AS Value FROM Customers WHERE Id = {customerId}")
                .SingleAsync();

            string fullNameOnDisk = await db.Database
                .SqlQuery<string>($"SELECT FullName AS Value FROM Customers WHERE Id = {customerId}")
                .SingleAsync();

            short storedKeyId = (short)((rawEmail[0] << 8) | rawEmail[1]);
            DemoConsole.Item("FullName on disk (plain)", fullNameOnDisk);
            DemoConsole.Item("Email on disk (base64)", DemoConsole.ShortB64(rawEmail));
            DemoConsole.Item("Email on disk length", $"{rawEmail.Length} bytes (30 header + {rawEmail.Length - 30} body)");
            DemoConsole.Item("Email header keyId", storedKeyId.ToString(System.Globalization.CultureInfo.InvariantCulture));
            DemoConsole.Note("The Email column holds ciphertext, not the readable address.");
        }

        // --- Read path: EF Core materializes and the converter decrypts transparently ---
        using (var scope = provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<DemoDbContext>();
            var loaded = await db.Customers.SingleAsync(c => c.Id == customerId);

            DemoConsole.Item("Decrypted FullName", loaded.FullName);
            DemoConsole.Item("Decrypted Email", loaded.Email);
            DemoConsole.Item("Decrypted NationalId", loaded.NationalId);

            if (loaded.Email == "ali.veli@example.com" && loaded.NationalId == "12345678901")
                DemoConsole.Ok("EF Core transparently decrypted both encrypted columns on read.");
            else
                DemoConsole.Note("Unexpected: materialized values did not match what was written.");
        }
    }
}
