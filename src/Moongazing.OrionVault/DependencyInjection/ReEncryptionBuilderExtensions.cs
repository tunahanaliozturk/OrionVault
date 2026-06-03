namespace Moongazing.OrionVault.DependencyInjection;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Hosting;
using Moongazing.OrionVault.Options;

/// <summary>
/// Fluent registration of the background re-encryption hosted service on the
/// <see cref="OrionVaultBuilder"/>.
/// </summary>
public static class ReEncryptionBuilderExtensions
{
    /// <summary>
    /// Register the <see cref="ReEncryptionHostedService"/> with the host. Requires an
    /// <see cref="IReEncryptionTarget"/> to be registered via
    /// <see cref="UseReEncryptionTarget{T}"/>; the service stays a no-op otherwise.
    /// </summary>
    /// <param name="builder">The OrionVault DI builder.</param>
    /// <param name="configure">Optional callback to tune <see cref="ReEncryptionOptions"/>.</param>
    /// <returns>The same builder for chaining.</returns>
    public static OrionVaultBuilder UseReEncryptionService(
        this OrionVaultBuilder builder,
        Action<ReEncryptionOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddOptions<ReEncryptionOptions>();
        if (configure is not null)
        {
            builder.Services.Configure(configure);
        }

        builder.Services.TryAddSingleton<IReEncryptionTarget, NullReEncryptionTarget>();
        builder.Services.AddHostedService<ReEncryptionHostedService>();

        return builder;
    }

    /// <summary>
    /// Register a singleton <see cref="IReEncryptionTarget"/> implementation. Replaces the
    /// default no-op target so the hosted service has work to do.
    /// </summary>
    public static OrionVaultBuilder UseReEncryptionTarget<T>(this OrionVaultBuilder builder)
        where T : class, IReEncryptionTarget
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.RemoveAll<IReEncryptionTarget>();
        builder.Services.AddSingleton<IReEncryptionTarget, T>();
        return builder;
    }

    private sealed class NullReEncryptionTarget : IReEncryptionTarget
    {
        public Task<int> ReEncryptBatchAsync(CancellationToken cancellationToken) =>
            Task.FromResult(0);
    }
}
