namespace Moongazing.OrionVault.Abstractions;

using Microsoft.EntityFrameworkCore;

/// <summary>
/// Scans an EF Core model and attaches value converters to properties marked
/// with <c>[Encrypted]</c> or via <c>IsEncrypted()</c>. Invoked by
/// <c>OrionVaultModelCustomizer</c> after EF Core's default customizer.
/// </summary>
/// <remarks>
/// This interface lives in the core package because the core's
/// <c>OrionVaultBuilder.UseEntityFrameworkCore</c> pattern is the only way to
/// wire it up. Implementations live in <c>Moongazing.OrionVault.EntityFrameworkCore</c>.
/// </remarks>
public interface IEncryptionConfigurator
{
    void Configure(ModelBuilder modelBuilder);
}
