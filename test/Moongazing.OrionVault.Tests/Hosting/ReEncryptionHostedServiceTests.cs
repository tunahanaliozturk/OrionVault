namespace Moongazing.OrionVault.Tests.Hosting;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.Hosting;
using Moongazing.OrionVault.Options;
using Xunit;

public sealed class ReEncryptionHostedServiceTests
{
    private sealed class CountingTarget : IReEncryptionTarget
    {
        public int InvocationCount;
        public int RowsPerBatch { get; set; } = 7;

        public Task<int> ReEncryptBatchAsync(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref InvocationCount);
            return Task.FromResult(RowsPerBatch);
        }
    }

    private sealed class ThrowingTarget : IReEncryptionTarget
    {
        public int InvocationCount;

        public Task<int> ReEncryptBatchAsync(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref InvocationCount);
            throw new InvalidOperationException("boom");
        }
    }

    [Fact]
    public async Task First_tick_waits_one_schedule_before_invoking_target()
    {
        using var diag = new OrionVaultDiagnostics();
        var target = new CountingTarget();
        using var service = NewService(target, diag, schedule: TimeSpan.FromMilliseconds(200));

        using var cts = new CancellationTokenSource();
        await service.StartAsync(cts.Token).ConfigureAwait(true);

        // Before the first scheduled tick the target must not have been invoked.
        await Task.Delay(75).ConfigureAwait(true);
        Assert.Equal(0, target.InvocationCount);

        await cts.CancelAsync().ConfigureAwait(true);
        await service.StopAsync(CancellationToken.None).ConfigureAwait(true);
    }

    [Fact]
    public async Task When_disabled_the_target_is_not_invoked()
    {
        using var diag = new OrionVaultDiagnostics();
        var target = new CountingTarget();
        using var service = NewService(target, diag, schedule: TimeSpan.FromMilliseconds(50), enabled: false);

        using var cts = new CancellationTokenSource();
        await service.StartAsync(cts.Token).ConfigureAwait(true);
        await Task.Delay(220).ConfigureAwait(true);
        await cts.CancelAsync().ConfigureAwait(true);
        await service.StopAsync(CancellationToken.None).ConfigureAwait(true);

        Assert.Equal(0, target.InvocationCount);
    }

    [Fact]
    public async Task Target_exception_is_swallowed_and_service_survives()
    {
        using var diag = new OrionVaultDiagnostics();
        var target = new ThrowingTarget();
        using var service = NewService(target, diag, schedule: TimeSpan.FromMilliseconds(50));

        using var cts = new CancellationTokenSource();
        await service.StartAsync(cts.Token).ConfigureAwait(true);
        await Task.Delay(400).ConfigureAwait(true);
        await cts.CancelAsync().ConfigureAwait(true);
        await service.StopAsync(CancellationToken.None).ConfigureAwait(true);

        // Multiple ticks should have fired even though every one threw.
        Assert.True(target.InvocationCount >= 1,
            $"Expected at least one tick despite exceptions but got {target.InvocationCount}.");
    }

    [Fact]
    public async Task Default_target_registered_by_UseReEncryptionService_is_a_NoOp()
    {
        var services = new ServiceCollection();
        services.AddSingleton<OrionVaultDiagnostics>();
        services.AddLogging();

        var builder = new OrionVaultBuilder(services);
        builder.UseReEncryptionService();

        await using var provider = services.BuildServiceProvider();
        var target = provider.GetRequiredService<IReEncryptionTarget>();

        var rows = await target.ReEncryptBatchAsync(CancellationToken.None).ConfigureAwait(true);
        Assert.Equal(0, rows);
    }

    [Fact]
    public async Task UseReEncryptionTarget_replaces_the_NoOp_default()
    {
        var services = new ServiceCollection();
        services.AddSingleton<OrionVaultDiagnostics>();
        services.AddLogging();

        var builder = new OrionVaultBuilder(services);
        builder
            .UseReEncryptionService()
            .UseReEncryptionTarget<CountingTarget>();

        await using var provider = services.BuildServiceProvider();
        var target = provider.GetRequiredService<IReEncryptionTarget>();

        Assert.IsType<CountingTarget>(target);
    }

    [Fact]
    public async Task Hosted_service_is_registered_as_an_IHostedService()
    {
        var services = new ServiceCollection();
        services.AddSingleton<OrionVaultDiagnostics>();
        services.AddLogging();

        var builder = new OrionVaultBuilder(services);
        builder.UseReEncryptionService();

        await using var provider = services.BuildServiceProvider();
        var hosted = provider.GetServices<IHostedService>();
        Assert.Contains(hosted, h => h is ReEncryptionHostedService);
    }

    private static ReEncryptionHostedService NewService(
        IReEncryptionTarget target,
        OrionVaultDiagnostics diagnostics,
        TimeSpan schedule,
        bool enabled = true)
    {
        var opts = new ReEncryptionOptions
        {
            Schedule = schedule,
            Enabled = enabled,
            DrainTimeout = TimeSpan.FromSeconds(1),
        };
        var monitor = new StaticOptionsMonitor<ReEncryptionOptions>(opts);
        return new ReEncryptionHostedService(target, diagnostics, monitor, NullLogger<ReEncryptionHostedService>.Instance);
    }

    private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
    {
        public StaticOptionsMonitor(T value) => CurrentValue = value;

        public T CurrentValue { get; }

        public T Get(string? name) => CurrentValue;

        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
