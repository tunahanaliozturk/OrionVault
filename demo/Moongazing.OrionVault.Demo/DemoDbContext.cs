namespace Moongazing.OrionVault.Demo;

using Microsoft.EntityFrameworkCore;

/// <summary>
/// Minimal demo DbContext. OrionVault's model customizer (wired via
/// <c>UseOrionVault(sp)</c>) scans <see cref="Customer"/> for <c>[Encrypted]</c>
/// properties and attaches the encrypting value converters; no per-property mapping
/// is needed here.
/// </summary>
public class DemoDbContext : DbContext
{
    public DemoDbContext(DbContextOptions<DemoDbContext> options) : base(options) { }

    public DbSet<Customer> Customers => Set<Customer>();
}
