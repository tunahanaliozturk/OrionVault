namespace Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.EntityFrameworkCore.Maintenance;

/// <summary>
/// Fluent registration of the v0.3.4 EF Core re-encryption / blind-index re-index runner on the
/// <see cref="OrionVaultBuilder"/>.
/// </summary>
public static class ReencryptionRunnerBuilderExtensions
{
    /// <summary>
    /// Registers <see cref="IEncryptionMaintenance"/> (implemented by
    /// <see cref="ReencryptionRunner"/>) as a singleton so an operator command, a one-shot
    /// migration, or a scheduled job can resolve it and run a re-encryption pass over a table.
    /// The runner picks up the registered <see cref="IEncryptor"/>, <see cref="IKeyProvider"/>,
    /// the optional <see cref="IBlindIndexProvider"/> (when <c>UseBlindIndex</c> was configured),
    /// and the optional <see cref="OrionVaultDiagnostics"/> for telemetry.
    /// </summary>
    /// <param name="builder">The OrionVault DI builder.</param>
    /// <returns>The same builder for chaining.</returns>
    /// <remarks>
    /// The runner itself is stateless and thread-safe; the per-run <see cref="Microsoft.EntityFrameworkCore.DbContext"/>
    /// is passed into <see cref="IEncryptionMaintenance.RunAsync"/> by the caller, so a singleton
    /// lifetime is correct and avoids capturing a scoped context.
    /// </remarks>
    public static OrionVaultBuilder UseReencryptionRunner(this OrionVaultBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.TryAddSingleton<IEncryptionMaintenance>(sp =>
            new ReencryptionRunner(
                sp.GetRequiredService<IEncryptor>(),
                sp.GetRequiredService<IKeyProvider>(),
                sp.GetService<IBlindIndexProvider>(),
                sp.GetService<OrionVaultDiagnostics>(),
                sp.GetService<ILogger<ReencryptionRunner>>()));

        return builder;
    }
}
