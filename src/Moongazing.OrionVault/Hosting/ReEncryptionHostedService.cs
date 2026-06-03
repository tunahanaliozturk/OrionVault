namespace Moongazing.OrionVault.Hosting;

using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.Options;

/// <summary>
/// Background service that periodically invokes a consumer-supplied
/// <see cref="IReEncryptionTarget"/> to re-encrypt rows still encrypted under retired keys.
/// Skips ticks when <see cref="ReEncryptionOptions.Enabled"/> is <see langword="false"/>.
/// On host shutdown, waits up to <see cref="ReEncryptionOptions.DrainTimeout"/> for the
/// current batch to complete.
/// </summary>
public sealed partial class ReEncryptionHostedService : BackgroundService
{
    private readonly IServiceScopeFactory scopeFactory;
    private readonly OrionVaultDiagnostics diagnostics;
    private readonly IOptionsMonitor<ReEncryptionOptions> options;
    private readonly ILogger<ReEncryptionHostedService> logger;

    /// <summary>Constructor.</summary>
    public ReEncryptionHostedService(
        IServiceScopeFactory scopeFactory,
        OrionVaultDiagnostics diagnostics,
        IOptionsMonitor<ReEncryptionOptions> options,
        ILogger<ReEncryptionHostedService> logger)
    {
        this.scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        this.diagnostics = diagnostics ?? throw new ArgumentNullException(nameof(diagnostics));
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // First tick after Schedule so a freshly-started host does not immediately churn the DB.
        try
        {
            await Task.Delay(options.CurrentValue.Schedule, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            var opts = options.CurrentValue;
            if (opts.Enabled)
            {
                await RunOneBatchAsync(stoppingToken).ConfigureAwait(false);
            }

            try
            {
                await Task.Delay(opts.Schedule, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private async Task RunOneBatchAsync(CancellationToken cancellationToken)
    {
        using var activity = diagnostics.ActivitySource.StartActivity("OrionVault.ReEncryptionBatch");
        var sw = Stopwatch.StartNew();
        try
        {
            // Fresh DI scope per batch so scoped consumer dependencies (DbContext etc.)
            // are not captured across the lifetime of the singleton hosted service.
            var scope = scopeFactory.CreateAsyncScope();
            await using (scope.ConfigureAwait(false))
            {
                var target = scope.ServiceProvider.GetRequiredService<IReEncryptionTarget>();
                var processed = await target.ReEncryptBatchAsync(cancellationToken).ConfigureAwait(false);
                diagnostics.ReEncryptionRowsProcessed.Add(processed);
                activity?.SetTag("orionvault.reencryption.rows_processed", processed);
                LogBatchOk(logger, processed, sw.Elapsed.TotalMilliseconds);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
#pragma warning disable CA1031 // bounded background service: log + survive
        catch (Exception ex)
#pragma warning restore CA1031
        {
            LogBatchFailed(logger, ex);
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
        }
        finally
        {
            diagnostics.ReEncryptionBatchDuration.Record(sw.Elapsed.TotalMilliseconds);
        }
    }

    /// <inheritdoc />
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        // The base StopAsync waits for ExecuteAsync to complete or the cancellation token
        // to fire. Cap the wait with the configured DrainTimeout so a stuck batch cannot
        // stall host shutdown.
        var drain = options.CurrentValue.DrainTimeout;
        using var combined = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        combined.CancelAfter(drain);
        await base.StopAsync(combined.Token).ConfigureAwait(false);
    }

    [LoggerMessage(EventId = 1, Level = LogLevel.Information,
        Message = "OrionVault re-encryption batch complete: {Rows} rows, {Elapsed:F1} ms")]
    private static partial void LogBatchOk(ILogger logger, int rows, double elapsed);

    [LoggerMessage(EventId = 2, Level = LogLevel.Error,
        Message = "OrionVault re-encryption batch failed; service will retry on next schedule")]
    private static partial void LogBatchFailed(ILogger logger, Exception exception);
}
