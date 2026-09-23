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
using Moongazing.OrionVault.Exceptions;
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

    // A source that hands over some rows and THEN fails, the way a connection dropping between
    // pages does. The rows it already yielded were really rotated and really written.
    private sealed class PartiallyFailingRotationSource : IRotationSource<int>
    {
        public Dictionary<int, byte[]> Rows { get; } = new();
        public List<int> Updated { get; } = [];

        public async IAsyncEnumerable<RotationCandidate<int>> EnumerateAsync(
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            foreach (var pair in Rows)
            {
                yield return new RotationCandidate<int>(pair.Key, pair.Value);
            }

            await Task.Yield();
            throw new InvalidOperationException("connection dropped between pages");
        }

        public Task UpdateAsync(int handle, byte[] ciphertext, CancellationToken cancellationToken)
        {
            Rows[handle] = ciphertext;
            Updated.Add(handle);
            return Task.CompletedTask;
        }
    }

    // A source registered SCOPED so the container disposes it at scope teardown - and whose
    // disposal throws, after the cycle has already completed and reported itself.
    private sealed class DisposalFailingRotationSource : IRotationSource<int>, IDisposable
    {
        public Dictionary<int, byte[]> Rows { get; } = new();

        public async IAsyncEnumerable<RotationCandidate<int>> EnumerateAsync(
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.Yield();
            foreach (var pair in Rows)
            {
                yield return new RotationCandidate<int>(pair.Key, pair.Value);
            }
        }

        public Task UpdateAsync(int handle, byte[] ciphertext, CancellationToken cancellationToken)
        {
            Rows[handle] = ciphertext;
            return Task.CompletedTask;
        }

        public void Dispose() => throw new InvalidOperationException("scope teardown exploded");
    }

    // Minimal capturing logger: the point of the test is that the failure is REPORTED, so the test
    // has to look at what was logged, not at a return value the caller never sees.
    private sealed class CapturingLogger<T> : ILogger<T>
    {
        private readonly List<(LogLevel Level, string Message, Exception? Exception)> entries = [];

        // A snapshot copy each time, so a caller can enumerate it while the background loop is
        // still appending.
        public List<(LogLevel Level, string Message, Exception? Exception)> Entries
        {
            get { lock (entries) { return [.. entries]; } }
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

        /// <summary>
        /// Waits for the SPECIFIC record a test is about, and returns that record.
        /// <para>
        /// Waiting on "any record exists" - or on a fixed delay - makes the assertion a property of
        /// how fast the machine is: it passes on a quiet runner and fails when three framework legs
        /// share one. Waiting on the condition removes that window instead of widening it. The
        /// timeout is generous because it is a backstop, not a tuning knob, and it fails loudly
        /// naming what WAS captured - falling through to a weaker assertion is how a timing window
        /// turns into a flaky test rather than a failing one.
        /// </para>
        /// </summary>
        public async Task<(LogLevel Level, string Message, Exception? Exception)> WaitForAsync(
            Func<(LogLevel Level, string Message, Exception? Exception), bool> match,
            string expectation)
        {
            ArgumentNullException.ThrowIfNull(match);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            while (true)
            {
                foreach (var entry in Entries)
                {
                    if (match(entry))
                    {
                        return entry;
                    }
                }

                if (timeout.IsCancellationRequested)
                {
                    var captured = Entries.Count == 0
                        ? "(nothing was logged at all)"
                        : string.Join(" | ", Entries.Select(e => $"[{e.Level}] {e.Message}"));
                    Assert.Fail($"Timed out after 30s waiting for {expectation}. Captured: {captured}");
                }

                await Task.Delay(10, CancellationToken.None).ConfigureAwait(false);
            }
        }
    }

    private const string KeyBase64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    // An interval long enough that ExecuteAsync's do/while runs its body EXACTLY ONCE and then
    // parks on the timer until StopAsync. These tests assert on the first cycle, and a second one
    // would report something different but equally correct - the part-way source has had its rows
    // rotated back into it by then, so cycle 2 legitimately says rotated=0 skipped=3. Bounding the
    // cycle count by construction is what makes that assertion deterministic instead of a race
    // against how quickly StopAsync lands.
    private static readonly TimeSpan SingleCycleInterval = TimeSpan.FromMinutes(10);

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
            Options.Create(new EncryptionRotationOptions { Interval = SingleCycleInterval }),
            logger,
            diagnostics);

        // The background loop runs its one cycle immediately; that one throws. Wait for the record
        // itself rather than for "something got logged", so the assertions below are not gated on a
        // timing window the test does not control.
        await sut.StartAsync(CancellationToken.None);
        var failed = await logger.WaitForAsync(
            e => e.Exception is OrionVaultRotationCycleException { InnerException: InvalidOperationException },
            "the cycle-failure record for a source that never yielded a row");
        await sut.StopAsync(CancellationToken.None);

        // Logged, at Error, still carrying the underlying cause so the failure is diagnosable: the
        // sweep wraps it to ferry the tallies out, and the original hangs off InnerException.
        Assert.Equal(LogLevel.Error, failed.Level);
        Assert.Contains("did NOT complete", failed.Message, StringComparison.Ordinal);

        // This source fails before yielding a single row, so zero really is the truth here - the
        // counterpart to the part-way test, which must report the rows it did rotate.
        Assert.Contains("scanned=0 rotated=0", failed.Message, StringComparison.Ordinal);

        // ... and counted, so a stalled rotation is visible on a dashboard and not only in logs.
        // Exactly once: StopAsync has awaited the loop, and only one cycle could ever run.
        Assert.Single(logger.Entries, e => e.Level == LogLevel.Error);
        Assert.Equal(1, Interlocked.Read(ref failures));
    }

    [Fact]
    public async Task A_cycle_that_fails_part_way_reports_the_rows_it_already_rotated_not_zero()
    {
        // Regression on the FIX, not the original defect: the cycle-failure report used to say "no
        // rows were processed" unconditionally, because the per-row tallies live inside the sweep
        // and the catch in ExecuteAsync could not see them - the same shape as the bug it replaced.
        // A sweep that rotates 3 rows and then loses its connection has really rotated them (the
        // writes are committed), and reporting that as nothing is worse than the old silence: it is
        // a confident false statement, so the operator has no reason to go and look.
        var key1 = KeyBase64;
        var key2 = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

        // Three rows on key 1, so all three need rotating under the active key 2. A fresh source
        // per run: rotating writes back through UpdateAsync, so a reused one would arrive at the
        // second run already migrated and report three skips instead of three rotations.
        PartiallyFailingRotationSource SeededSource()
        {
            var seed = new ServiceCollection();
            seed.AddOrionVault(o =>
            {
                o.UseStaticKeys(k => { k.Add(1, key1); k.Add(2, key2); });
                o.ActiveKeyId = 1;
            });
            using var seedSp = seed.BuildServiceProvider();
            var seedEncryptor = seedSp.GetRequiredService<IEncryptor>();
            var seeded = new PartiallyFailingRotationSource();
            seeded.Rows[1] = seedEncryptor.EncryptBytes([1]);
            seeded.Rows[2] = seedEncryptor.EncryptBytes([2]);
            seeded.Rows[3] = seedEncryptor.EncryptBytes([3]);
            return seeded;
        }

        ServiceProvider HostFor(IRotationSource<int> rotationSource)
        {
            var services = new ServiceCollection();
            services.AddOrionVault(o =>
            {
                o.UseStaticKeys(k => { k.Add(1, key1); k.Add(2, key2); });
                o.ActiveKeyId = 2;
            });
            services.AddSingleton(rotationSource);
            return services.BuildServiceProvider();
        }

        // Called directly, the failure carries the tallies, so an on-demand operator trigger gets
        // the same honest account the background loop does.
        var directSource = SeededSource();
        await using (var directSp = HostFor(directSource))
        {
            using var direct = NewHost(directSp);
            var thrown = await Assert.ThrowsAsync<OrionVaultRotationCycleException>(
                () => direct.RunCycleAsync(CancellationToken.None));

            Assert.Equal(3, thrown.Partial.Scanned);
            Assert.Equal(3, thrown.Partial.Rotated);
            Assert.Equal(0, thrown.Partial.Skipped);
            Assert.Equal(0, thrown.Partial.Errors);
            Assert.Equal(3, directSource.Updated.Count); // really written before the failure
        }

        // ... and the same counts reach the background loop's catch, which is what proves they are
        // reachable from there at all rather than reconstructed after the fact.
        var source = SeededSource();
        await using var sp = HostFor(source);
        var diagnostics = sp.GetRequiredService<OrionVaultDiagnostics>();
        var failures = 0L;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
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
            Options.Create(new EncryptionRotationOptions { Interval = SingleCycleInterval }),
            logger,
            diagnostics);

        // Wait for the cycle-failure record itself, not for "something got logged". The rows this
        // source hands over get written straight back into it by UpdateAsync, so a SECOND cycle
        // would find them already on the active key and report rotated=0 skipped=3 - correct for
        // that cycle, and nothing to do with the one under test. SingleCycleInterval makes a second
        // cycle impossible rather than merely unlikely.
        await sut.StartAsync(CancellationToken.None);
        var failed = await logger.WaitForAsync(
            e => e.Level == LogLevel.Error && e.Exception is OrionVaultRotationCycleException,
            "the cycle-failure record for the one cycle this test runs");
        await sut.StopAsync(CancellationToken.None);

        // The rows it rotated are named, and named as PARTIAL - "rotated=3" alone would read as a
        // completed cycle to someone deciding whether to re-run.
        Assert.Contains("rotated=3", failed.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("rotated=0", failed.Message, StringComparison.Ordinal);
        Assert.Contains("did NOT complete", failed.Message, StringComparison.Ordinal);
        Assert.Contains("Partial counts", failed.Message, StringComparison.Ordinal);

        // Exactly one cycle ran, so exactly one failure is recorded and counted. StopAsync has
        // awaited the loop, so the counter increment that follows the log has certainly landed.
        Assert.Single(logger.Entries, e => e.Level == LogLevel.Error);
        Assert.Equal(1, Interlocked.Read(ref failures));
    }

    [Fact]
    public async Task A_cycle_that_completes_then_faults_disposing_its_scope_is_not_counted_as_a_failed_cycle()
    {
        // The other shape the review named: the sweep finished and already emitted its duration,
        // last-cycle snapshot, log line and observer callback - then teardown threw. That is not an
        // incomplete cycle, and counting it would pair a cycle_failures increment with a full set
        // of row counters, which would teach an operator to distrust the pairing. It gets its own
        // warning and no counter.
        // Not disposed by the test on purpose: the per-cycle scope disposes it, and that disposal
        // throwing is the entire scenario. Disposing it here would just move the throw.
#pragma warning disable CA2000
        var source = new DisposalFailingRotationSource();
#pragma warning restore CA2000
        var services = new ServiceCollection();
        services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, KeyBase64));
            o.ActiveKeyId = 1;
        });
        // Scoped, so the container disposes it when the per-cycle scope is torn down.
        services.AddScoped<IRotationSource<int>>(_ => source);
        await using var sp = services.BuildServiceProvider();

        var encryptor = sp.GetRequiredService<IEncryptor>();
        source.Rows[1] = encryptor.EncryptBytes([9]); // already on the active key: one clean skip

        var diagnostics = sp.GetRequiredService<OrionVaultDiagnostics>();
        var failures = 0L;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
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
            Options.Create(new EncryptionRotationOptions()),
            logger,
            diagnostics);

        // The cycle returns its real result: the disposal fault does not rewrite the outcome.
        var result = await sut.RunCycleAsync(CancellationToken.None);

        Assert.Equal(1, result.Scanned);
        Assert.Equal(1, result.Skipped);
        Assert.Equal(0, result.Errors);

        // Reported, but on its own channel and at Warning - distinguishable from a sweep that
        // stopped part-way.
        var disposal = logger.Entries.Where(e => e.Exception is InvalidOperationException).ToList();
        Assert.NotEmpty(disposal);
        Assert.All(disposal, e => Assert.Equal(LogLevel.Warning, e.Level));
        Assert.All(disposal, e => Assert.Contains("disposing its service scope", e.Message, StringComparison.Ordinal));

        // And NOT counted as a failed cycle.
        Assert.Equal(0, Interlocked.Read(ref failures));
        Assert.DoesNotContain(logger.Entries, e => e.Level == LogLevel.Error);
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
