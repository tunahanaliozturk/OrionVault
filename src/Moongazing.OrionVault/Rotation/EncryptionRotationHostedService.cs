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

    [LoggerMessage(EventId = 4, Level = LogLevel.Error,
        Message = "EncryptionRotation cycle did NOT complete. Partial counts at the point of failure: " +
                  "scanned={Scanned} rotated={Rotated} skipped={Skipped} errors={Errors}. Rotated rows are " +
                  "already committed; the next tick retries the remainder")]
    private partial void LogCycleFailed(int scanned, int rotated, int skipped, int errors, Exception ex);

    [LoggerMessage(EventId = 5, Level = LogLevel.Warning,
        Message = "EncryptionRotation cycle completed and reported its tallies, then faulted while disposing its " +
                  "service scope; the cycle's results stand and it is NOT counted as a failed cycle")]
    private partial void LogScopeDisposalFailed(Exception ex);

    private readonly IServiceScopeFactory scopeFactory;
    private readonly EncryptionRotationOptions options;
    private readonly ILogger<EncryptionRotationHostedService<THandle>> logger;
    private readonly OrionVaultDiagnostics? diagnostics;

    public EncryptionRotationHostedService(
        IServiceScopeFactory scopeFactory,
        IOptions<EncryptionRotationOptions> options,
        ILogger<EncryptionRotationHostedService<THandle>>? logger = null,
        OrionVaultDiagnostics? diagnostics = null)
    {
        ArgumentNullException.ThrowIfNull(scopeFactory);
        ArgumentNullException.ThrowIfNull(options);
        this.scopeFactory = scopeFactory;
        this.options = options.Value;
        this.options.ValidateAndNormalise();
        this.logger = logger ?? NullLogger<EncryptionRotationHostedService<THandle>>.Instance;
        // Held directly rather than resolved per cycle, because the cycle-failure path must be able
        // to report even when creating the scope is the thing that failed.
        this.diagnostics = diagnostics;
    }

    /// <summary>
    /// Run a single rotation pass. Exposed for tests + on-demand operator triggers.
    /// </summary>
    /// <exception cref="Exceptions.OrionVaultRotationCycleException">
    /// The sweep started and then failed part-way. Its <c>Partial</c> carries the tallies at the
    /// instant of the throw, so a caller can report what the cycle really did instead of implying
    /// nothing happened. A failure before the first row is not wrapped.
    /// </exception>
    public async Task<RotationCycleResult> RunCycleAsync(CancellationToken cancellationToken)
    {
        var scope = scopeFactory.CreateAsyncScope();
        try
        {
            return await RunSweepAsync(scope, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Tearing the scope down must never change the account the cycle just gave. On the
            // success path a disposal fault would otherwise surface to ExecuteAsync as a cycle
            // failure although the cycle completed and already emitted its duration, snapshot, log
            // line and observer callback - counting that would pair a cycle_failures increment
            // with a full set of row counters and make the pairing meaningless. On the failure path
            // it would mask the real cause. It gets its own warning instead, the same fate model
            // the ProgressCallback and IKeyRotationObserver faults already have here.
            try
            {
                await scope.DisposeAsync().ConfigureAwait(false);
            }
#pragma warning disable CA1031 // a faulting teardown is reported, never allowed to rewrite the outcome
            catch (Exception disposeEx)
#pragma warning restore CA1031
            {
                LogScopeDisposalFailed(disposeEx);
            }
        }
    }

    private async Task<RotationCycleResult> RunSweepAsync(AsyncServiceScope scope, CancellationToken cancellationToken)
    {
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
        try
        {
#pragma warning disable CA2007 // await foreach over IAsyncEnumerable handles configure-await semantics through the enumerator
            await foreach (var candidate in source.EnumerateAsync(cancellationToken))
#pragma warning restore CA2007
            {
                cancellationToken.ThrowIfCancellationRequested();
                scanned++;
                try
                {
                    // Inside the per-row guard: NeedsRotation rejects a blob too short to be an
                    // envelope, and that verdict belongs in the error count next to a failed decrypt -
                    // not escaping the loop and taking the whole cycle down.
                    if (!EncryptionRotator.NeedsRotation(candidate.Ciphertext, activeKeyId))
                    {
                        skipped++;
                        diagnostics?.RotationRowsSkipped.Add(1);
                        continue;
                    }

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
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
#pragma warning disable CA1031 // wrapped, not swallowed: the tallies have to travel with the failure
        catch (Exception ex)
#pragma warning restore CA1031
        {
            // The sweep stopped part-way: the source stopped producing between pages, a write
            // failed outside the per-row guard. Whatever it already rotated IS rotated - those
            // writes are committed - so the failure has to carry the tallies rather than let the
            // caller assume zero. They are read HERE, in the scope that incremented them and at the
            // instant of the throw, not reconstructed afterwards: the whole point of the original
            // defect was a failure path that could not see what the cycle had done.
            throw new Exceptions.OrionVaultRotationCycleException(
                $"EncryptionRotation cycle failed after scanning {scanned} row(s) " +
                $"(rotated={rotated} skipped={skipped} errors={errors}); these counts are partial.",
                new RotationCycleResult(scanned, rotated, skipped, errors),
                ex);
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
#pragma warning disable CA1031 // the loop must survive any cycle-level fault; it is reported, not swallowed
            catch (Exception ex)
#pragma warning restore CA1031
            {
                // Cycle-level failure: a bad connection string, a migration holding a lock, a
                // revoked permission, a connection dropping between pages. Every end-of-cycle
                // signal (RotationCycleDuration, SetLastCycleSnapshot, the last-cycle gauges) sits
                // past the throw and never fires, so swallowing this silently is what leaves the
                // service alive and healthy-looking while rotation has not completed once.
                //
                // Report what the cycle ACTUALLY did. A sweep that rotated four thousand rows and
                // then lost its connection has really rotated them, and telling the operator
                // "nothing happened" is a confident false statement - worse than the silence it
                // replaced, because it gives them no reason to go and look. RunCycleAsync wraps a
                // part-way failure in OrionVaultRotationCycleException carrying the tallies as of
                // the throw; anything else never reached a row, so zero is the truth there.
                var partial = (ex as Exceptions.OrionVaultRotationCycleException)?.Partial
                    ?? RotationCycleResult.Empty;
                LogCycleFailed(partial.Scanned, partial.Rotated, partial.Skipped, partial.Errors, ex);
                diagnostics?.RotationCycleFailures.Add(1);

                // Deliberately NOT feeding SetLastCycleSnapshot here. Those gauges - and
                // last_cycle_at_unix_seconds especially - are the "rotation completed recently"
                // liveness signal; writing a failed cycle into them would make a stalled host look
                // freshly swept, which is the exact reading this whole fix exists to prevent. The
                // per-row counters already carry the partial work, because they were incremented
                // row by row as it happened.
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
    }
}

/// <summary>Snapshot of one rotation cycle's tallies.</summary>
public sealed record RotationCycleResult(int Scanned, int Rotated, int Skipped, int Errors)
{
    /// <summary>All counters zero - the state of a cycle that failed before reaching a row.</summary>
    public static RotationCycleResult Empty { get; } = new(0, 0, 0, 0);
}

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
