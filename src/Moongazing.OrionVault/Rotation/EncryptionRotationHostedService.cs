namespace Moongazing.OrionVault.Rotation;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;

/// <summary>
/// Background service that walks an <see cref="IRotationSource{THandle}"/>, calls
/// <see cref="EncryptionRotator.NeedsRotation"/> on each row, and re-encrypts the rows
/// that are still on a non-active key. Pairs with consumers who roll the active key id
/// on their <see cref="IKeyProvider"/> and want a periodic re-encryption sweep instead
/// of a one-shot script.
/// </summary>
public sealed partial class EncryptionRotationHostedService<THandle> : BackgroundService
{
    [LoggerMessage(EventId = 1, Level = LogLevel.Information,
        Message = "EncryptionRotation cycle complete: scanned={Scanned} rotated={Rotated} skipped={Skipped} errors={Errors} duration={Duration}")]
    private partial void LogCycle(int scanned, int rotated, int skipped, int errors, TimeSpan duration);

    [LoggerMessage(EventId = 2, Level = LogLevel.Error,
        Message = "EncryptionRotation row failed (rotated={Rotated} so far this cycle)")]
    private partial void LogRowFailed(int rotated, Exception ex);

    [LoggerMessage(EventId = 3, Level = LogLevel.Warning,
        Message = "IKeyRotationObserver faulted; rotation sweep continued")]
    private partial void LogObserverFaulted(Exception ex);

    private readonly IServiceScopeFactory scopeFactory;
    private readonly EncryptionRotationOptions options;
    private readonly ILogger<EncryptionRotationHostedService<THandle>> logger;

    public EncryptionRotationHostedService(
        IServiceScopeFactory scopeFactory,
        IOptions<EncryptionRotationOptions> options,
        ILogger<EncryptionRotationHostedService<THandle>>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(scopeFactory);
        ArgumentNullException.ThrowIfNull(options);
        this.scopeFactory = scopeFactory;
        this.options = options.Value;
        this.options.ValidateAndNormalise();
        this.logger = logger ?? NullLogger<EncryptionRotationHostedService<THandle>>.Instance;
    }

    /// <summary>Run a single rotation pass. Exposed for tests + on-demand operator triggers.</summary>
    public async Task<RotationCycleResult> RunCycleAsync(CancellationToken cancellationToken)
    {
        var scope = scopeFactory.CreateAsyncScope();
        await using var _ = scope.ConfigureAwait(false);
        var encryptor = scope.ServiceProvider.GetRequiredService<IEncryptor>();
        var keys = scope.ServiceProvider.GetRequiredService<IKeyProvider>();
        var source = scope.ServiceProvider.GetRequiredService<IRotationSource<THandle>>();
        var diagnostics = scope.ServiceProvider.GetService<OrionVaultDiagnostics>();
        var activeKeyId = keys.ActiveKeyId;

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var scanned = 0;
        var rotated = 0;
        var skipped = 0;
        var errors = 0;
#pragma warning disable CA2007 // await foreach over IAsyncEnumerable handles configure-await semantics through the enumerator
        await foreach (var candidate in source.EnumerateAsync(cancellationToken))
#pragma warning restore CA2007
        {
            cancellationToken.ThrowIfCancellationRequested();
            scanned++;
            if (!EncryptionRotator.NeedsRotation(candidate.Ciphertext, activeKeyId))
            {
                skipped++;
                diagnostics?.RotationRowsSkipped.Add(1);
                continue;
            }
            try
            {
                var fresh = EncryptionRotator.Rotate(encryptor, candidate.Ciphertext);
                await source.UpdateAsync(candidate.Handle, fresh, cancellationToken).ConfigureAwait(false);
                rotated++;
                diagnostics?.RotationRowsRotated.Add(1);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
#pragma warning disable CA1031 // background loop swallows one-row failures so a single malformed blob does not abort the pass
            catch (Exception ex)
#pragma warning restore CA1031
            {
                errors++;
                diagnostics?.RotationRowErrors.Add(1);
                LogRowFailed(rotated, ex);
            }
            if (options.MaxRowsPerCycle is { } cap && rotated >= cap)
            {
                break;
            }
        }
        sw.Stop();
        diagnostics?.RotationCycleDuration.Record(sw.Elapsed.TotalMilliseconds);
        // v0.2.15: feed the last-cycle ObservableGauges so operators see a "right-now"
        // snapshot of what the most recent sweep produced.
        diagnostics?.SetLastCycleSnapshot(scanned, rotated, skipped, errors);
        LogCycle(scanned, rotated, skipped, errors, sw.Elapsed);
        var result = new RotationCycleResult(scanned, rotated, skipped, errors);
        // v0.2.14 ProgressCallback: invoked AFTER OTel + log so observers see the same
        // totals. A throwing callback must not abort the rotation sweep - the sweep is
        // the load-bearing path, the callback is observability.
        if (options.ProgressCallback is { } cb)
        {
            try
            {
                cb(result);
            }
#pragma warning disable CA1031
            catch
#pragma warning restore CA1031
            {
                // Callback faults are observed via the existing OrionVaultDiagnostics
                // counters; they should not bubble up and skip the next cycle.
            }
        }
        // v0.2.20 IKeyRotationObserver: DI-registered alternative to the options-based
        // ProgressCallback. Resolved from the per-cycle scope (same scope the encryptor
        // and key provider come from). Skipped when no observer is registered AND when a
        // NullKeyRotationObserver is registered (the same null-or-Null convention used
        // by the v0.2.19 decryption failure handler and v0.2.18 patch dead-letter sink).
        var observer = scope.ServiceProvider.GetService<Abstractions.IKeyRotationObserver>();
        if (observer is not null and not Abstractions.NullKeyRotationObserver)
        {
            try
            {
                observer.OnRotationCycleCompleted(result);
            }
#pragma warning disable CA1031
            catch (Exception observerEx)
#pragma warning restore CA1031
            {
                // Same fate model as the ProgressCallback: faults do not abort the
                // sweep. Logged so operators can trace observer regressions, matching
                // the public IKeyRotationObserver contract that says faults are
                // "caught and logged".
                LogObserverFaulted(observerEx);
            }
        }
        return result;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(options.Interval);
        do
        {
            try
            {
                await RunCycleAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
#pragma warning disable CA1031
            catch
#pragma warning restore CA1031
            {
                // Cycle-level failure: the next tick re-attempts. Per-row failures are
                // already counted above and do not bubble.
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
    }
}

/// <summary>Snapshot of one rotation cycle's tallies.</summary>
public sealed record RotationCycleResult(int Scanned, int Rotated, int Skipped, int Errors);

/// <summary>Configuration for <see cref="EncryptionRotationHostedService{THandle}"/>.</summary>
public sealed class EncryptionRotationOptions
{
    /// <summary>Interval between rotation cycles. Default 6 hours.</summary>
    public TimeSpan Interval { get; set; } = TimeSpan.FromHours(6);

    /// <summary>Upper bound on rows rotated per cycle. Null = unlimited.</summary>
    public int? MaxRowsPerCycle { get; set; }

    /// <summary>
    /// v0.2.14 optional per-cycle progress callback. Invoked AFTER OTel emission so
    /// custom dashboards / log shippers / operator notifiers see the same totals the
    /// metrics see. Exceptions thrown by the callback are caught and swallowed so a
    /// faulty notifier does not abort the rotation sweep.
    /// </summary>
    public Action<RotationCycleResult>? ProgressCallback { get; set; }

    internal void ValidateAndNormalise()
    {
        if (Interval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(Interval), Interval, "EncryptionRotationOptions.Interval must be positive.");
        }
        if (MaxRowsPerCycle is { } cap && cap < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaxRowsPerCycle), MaxRowsPerCycle,
                "EncryptionRotationOptions.MaxRowsPerCycle must be at least 1 when specified.");
        }
    }
}
