using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;
using Moongazing.OrionVault.Sample;

if (File.Exists("sample.db")) File.Delete("sample.db");

var services = new ServiceCollection()
    .AddLogging(b => b.AddConsole().SetMinimumLevel(LogLevel.Warning))
    .AddOrionVault(o =>
    {
        o.UseStaticKeys(k =>
            k.Add(keyId: 1, base64Key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        o.ActiveKeyId = 1;
    })
    .UseEntityFrameworkCore<SampleDbContext>()
    .Services
    .AddDbContext<SampleDbContext>((sp, opt) =>
        opt.UseSqlite("Data Source=sample.db").UseOrionVault(sp))
    .BuildServiceProvider();

using var scope = services.CreateScope();
var db = scope.ServiceProvider.GetRequiredService<SampleDbContext>();
await db.Database.EnsureCreatedAsync();

db.Customers.Add(new Customer
{
    Id = Guid.NewGuid(),
    FullName = "Ali Veli",
    Email = "ali@example.com",
    IbanLast4 = "1234"
});
await db.SaveChangesAsync();
Console.WriteLine("Yazildi.");

var raw = await db.Database
    .SqlQuery<byte[]>($"SELECT Email AS Value FROM Customers")
    .SingleAsync();
Console.WriteLine($"Raw bytes in DB (first 6 hex): {Convert.ToHexString(raw[..6])}");
Console.WriteLine($"Raw length: {raw.Length} bytes (30 header + {raw.Length - 30} body)");

db.ChangeTracker.Clear();
var loaded = await db.Customers.FirstAsync();
Console.WriteLine($"Decrypted Email: {loaded.Email}");
Console.WriteLine($"Decrypted IbanLast4: {loaded.IbanLast4}");
