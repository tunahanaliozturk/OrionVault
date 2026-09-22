namespace Moongazing.OrionVault.Tests;

using System.Diagnostics.Metrics;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.Rotation;
using Xunit;

public sealed class EncryptionRotationHostedServiceTests
{
    private sealed class InMemoryRotationSource : IRotationSource<int>
    {
        public Dictionary<int, byte[]> Rows { get; } = new();
        public List<(int Handle, byte[] Fresh)> Updates { get; } = new();
#pragma warning disable CS1998
        public async IAsyncEnumerable<RotationCandidate<int>> EnumerateAsync(
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            foreach (var pair in Rows)
            {
                yield return new RotationCandidate<int>(pair.Key, pair.Value);
            }
        }
#pragma warning restore CS1998
        public Task UpdateAsync(int handle, byte[] ciphertext, CancellationToken cancellationToken)
        {
            Rows[handle] = ciphertext;
            Updates.Add((handle, ciphertext));
            return Task.CompletedTask;
        }
    }

    // A source that fails the way a bad connection string / held migration lock / revoked
    // permission does: the failure lands on the FIRST enumeration, so no row is ever reached.
    private sealed class FailingRotationSource : IRotationSource<int>
    {
        public IAsyncEnumerable<RotationCandidate<int>> EnumerateAsync(CancellationToken cancellationToken)
            => throw new InvalidOperationException("rotation source unreachable");

        public Task UpdateAsync(int handle, byte[] ciphertext, CancellationToken cancellationToken)
            => Task.CompletedTask;
    }

    // Minimal capturing logger: the point of the test is that the failure is REPORTED, so the test
    // has to look at what was logged, not at a return value the caller never sees.
    private sealed class CapturingLogger<T> : ILogger<T>
    {
        private readonly List<(LogLevel Level, string Message, Exception? Exception)> entries = [];

        public IReadOnlyList<(LogLevel Level, string Message, Exception? Exception)> Entries
        {
            get { lock (entries) { return entries.ToList(); } }
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            ArgumentNullException.ThrowIfNull(formatter);
            lock (entries)
            {
                entries.Add((logLevel, formatter(state, exception), exception));
            }
        }
    }

    private const string KeyBase64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    private static (ServiceProvider sp, InMemoryRotationSource source) BuildHost(short activeKeyId)
    {
        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k =>
            {
                k.Add(1, KeyBase64);
                k.Add(2, Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));
            });
            o.ActiveKeyId = activeKeyId;
        });
        var source = new InMemoryRotationSource();
        services.AddSingleton<IRotationSource<int>>(source);
        var sp = services.BuildServiceProvider();
        return (sp, source);
    }

    private static EncryptionRotationHostedService<int> NewHost(ServiceProvider sp, EncryptionRotationOptions? opts = null)
        => new(
            sp.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(opts ?? new EncryptionRotationOptions()));

    [Fact]
    public async Task RunCycleAsync_rotates_rows_on_a_non_active_key_and_skips_rows_on_active_key()
    {
        // Encrypt under key id 1 first, then bump active to 2 to require rotation.
        var (firstSp, source) = BuildHost(activeKeyId: 1);
        try
        {
            var encryptor = firstSp.GetRequiredService<IEncryptor>();
            source.Rows[10] = encryptor.EncryptBytes(new byte[] { 1, 2, 3 });
        }
        finally
        {
            await firstSp.DisposeAsync();
        }

        // Build a NEW host whose active key id is 2.
        var (sp, _) = BuildHost(activeKeyId: 2);
        // Wire the same source we just seeded.
        var collection = new ServiceCollection();
        collection.AddOrionVault(o =>
        {
            o.UseStaticKeys(k =>
            {
                k.Add(1, KeyBase64);
                k.Add(2, Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));
            });
            o.ActiveKeyId = 2;
        });
        collection.AddSingleton<IRotationSource<int>>(source);
        await using var hostSp = collection.BuildServiceProvider();
        using var sut = NewHost(hostSp);

        var result = await sut.RunCycleAsync(CancellationToken.None);

        Assert.Equal(1, result.Scanned);
        Assert.Equal(1, result.Rotated);
        Assert.Equal(0, result.Skipped);
        Assert.Single(source.Updates);

        // The freshly rotated ciphertext should now read back under the new active key.
        var afterEncryptor = hostSp.GetRequiredService<IEncryptor>();
        Assert.Equal(new byte[] { 1, 2, 3 }, afterEncryptor.DecryptBytes(source.Updates[0].Fresh));
    }

    [Fact]
    public async Task RunCycleAsync_skips_rows_already_on_active_key()
    {
        var (sp, source) = BuildHost(activeKeyId: 1);
        var encryptor = sp.GetRequiredService<IEncryptor>();
        source.Rows[10] = encryptor.EncryptBytes(new byte[] { 9, 9 });

        using var sut = NewHost(sp);
        var result = await sut.RunCycleAsync(CancellationToken.None);

        Assert.Equal(1, result.Scanned);
        Assert.Equal(0, result.Rotated);
        Assert.Equal(1, result.Skipped);
        Assert.Empty(source.Updates);
        await sp.DisposeAsync();
    }

    [Fact]
    public async Task RunCycleAsync_caps_rotations_at_MaxRowsPerCycle()
    {
        // Three rows all on the previous key.
        var (firstSp, source) = BuildHost(activeKeyId: 1);
        try
        {
            var encryptor = firstSp.GetRequiredService<IEncryptor>();
            source.Rows[1] = encryptor.EncryptBytes(new byte[] { 1 });
            source.Rows[2] = encryptor.EncryptBytes(new byte[] { 2 });
            source.Rows[3] = encryptor.EncryptBytes(new byte[] { 3 });
        }
        finally
        {
            await firstSp.DisposeAsync();
        }

        var collection = new ServiceCollection();
        collection.AddOrionVault(o =>
        {
            o.UseStaticKeys(k =>
            {
                k.Add(1, KeyBase64);
                k.Add(2, Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));
            });
            o.ActiveKeyId = 2;
        });
        collection.AddSingleton<IRotationSource<int>>(source);
        await using var hostSp = collection.BuildServiceProvider();
        using var sut = NewHost(hostSp, new EncryptionRotationOptions { MaxRowsPerCycle = 2 });

        var result = await sut.RunCycleAsync(CancellationToken.None);

        Assert.Equal(2, result.Rotated);
    }

    [Fact]
    public async Task RunCycleAsync_counts_a_value_too_short_to_be_an_envelope_as_an_error_not_a_skip()
    {
        // A row holding a value that is not an envelope - a plaintext leftover, a truncated blob -
        // whose first two bytes happen to equal the ACTIVE key id (0x00 0x01 == 1). It used to read
        // as "already on the active key" and land in the skipped column, so a cycle over a table
        // full of them reported a clean sweep. It is a failed row, and the cycle carries on past it
        // rather than dying on it.
        var (sp, source) = BuildHost(activeKeyId: 1);
        var encryptor = sp.GetRequiredService<IEncryptor>();
        source.Rows[1] = [0x00, 0x01, .. "not a ciphertext"u8];
        source.Rows[2] = encryptor.EncryptBytes([7, 7]); // healthy, already on the active key

        using var sut = NewHost(sp);
        var result = await sut.RunCycleAsync(CancellationToken.None);

        Assert.Equal(2, result.Scanned);
        Assert.Equal(1, result.Errors);
        Assert.Equal(1, result.Skipped);
        Assert.Equal(0, result.Rotated);
        Assert.Empty(source.Updates);
        await sp.DisposeAsync();
    }

    [Fact]
    public async Task A_cycle_that_fails_outright_is_logged_and_counted_instead_of_swallowed()
    {
        // Regression: ExecuteAsync used to catch cycle-level failures with a bare `catch { }`. When
        // EnumerateAsync throws every cycle - bad connection string, a migration holding a lock, a
        // permission change - no row is reached, so no per-row counter increments, and the cycle
        // duration histogram, the last-cycle snapshot gauges and the row-error counter all sit PAST
        // the throw and never emit either. The service stayed alive and perfectly healthy-looking
        // while rotation never happened once. The class already used [LoggerMessage] for row
        // failures and observer faults, so this one path was silent on every channel an operator
        // has.
        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, KeyBase64));
            o.ActiveKeyId = 1;
        });
        services.AddSingleton<IRotationSource<int>>(new FailingRotationSource());
        await using var sp = services.BuildServiceProvider();

        var diagnostics = sp.GetRequiredService<OrionVaultDiagnostics>();
        var failures = 0L;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            // Filter on the diagnostics INSTANCE, not the meter name: a sibling test class can
            // leave another OrionVaultDiagnostics publishing under the same name.
            if (ReferenceEquals(instrument.Meter, diagnostics.Meter)
                && instrument.Name == "orion.vault.rotation.cycle_failures")
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, val, _, _) => Interlocked.Add(ref failures, val));
        listener.Start();

        var logger = new CapturingLogger<EncryptionRotationHostedService<int>>();
        using var sut = new EncryptionRotationHostedService<int>(
            sp.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new EncryptionRotationOptions { Interval = TimeSpan.FromMilliseconds(20) }),
            logger,
            diagnostics);

        // The background loop runs its first cycle immediately; that one throws.
        await sut.StartAsync(CancellationToken.None);
        using (var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
        {
            while (logger.Entries.Count == 0 && !timeout.IsCancellationRequested)
            {
                await Task.Delay(10, CancellationToken.None);
            }
        }

        await sut.StopAsync(CancellationToken.None);

        // Logged, at Error, carrying the underlying exception so the cause is diagnosable.
        var failed = logger.Entries.Where(e => e.Exception is InvalidOperationException).ToList();
        Assert.NotEmpty(failed);
        Assert.All(failed, e => Assert.Equal(LogLevel.Error, e.Level));
        Assert.Contains(failed, e => e.Message.Contains("cycle failed", StringComparison.OrdinalIgnoreCase));

        // ... and counted, so a stalled rotation is visible on a dashboard and not only in logs.
        Assert.True(Interlocked.Read(ref failures) > 0);
    }

    [Fact]
    public void Options_validate_at_construction()
    {
        var (sp, _) = BuildHost(activeKeyId: 1);
        try
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                NewHost(sp, new EncryptionRotationOptions { Interval = TimeSpan.Zero }));
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                NewHost(sp, new EncryptionRotationOptions { MaxRowsPerCycle = 0 }));
        }
        finally
        {
            sp.Dispose();
        }
    }
}
