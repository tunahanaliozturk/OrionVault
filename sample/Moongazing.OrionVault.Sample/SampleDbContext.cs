namespace Moongazing.OrionVault.Sample;

using Microsoft.EntityFrameworkCore;

public class SampleDbContext : DbContext
{
    public SampleDbContext(DbContextOptions<SampleDbContext> opt) : base(opt) { }
    public DbSet<Customer> Customers => Set<Customer>();
}
