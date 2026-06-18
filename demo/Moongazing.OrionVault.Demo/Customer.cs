namespace Moongazing.OrionVault.Demo;

using Moongazing.OrionVault.EntityFrameworkCore;

/// <summary>
/// Demo entity. <see cref="Email"/> and <see cref="NationalId"/> are marked
/// <c>[Encrypted]</c> so OrionVault's value converter encrypts them on write and
/// decrypts them on read. <see cref="FullName"/> stays plaintext for contrast.
/// </summary>
public class Customer
{
    public Guid Id { get; set; }

    public string FullName { get; set; } = null!;

    [Encrypted]
    public string Email { get; set; } = null!;

    [Encrypted]
    public string NationalId { get; set; } = null!;
}
