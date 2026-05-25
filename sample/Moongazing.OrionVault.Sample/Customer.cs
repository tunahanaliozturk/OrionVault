namespace Moongazing.OrionVault.Sample;

using Moongazing.OrionVault.EntityFrameworkCore;

public class Customer
{
    public Guid Id { get; set; }
    public string FullName { get; set; } = null!;

    [Encrypted]
    public string Email { get; set; } = null!;

    [Encrypted]
    public string IbanLast4 { get; set; } = null!;
}
