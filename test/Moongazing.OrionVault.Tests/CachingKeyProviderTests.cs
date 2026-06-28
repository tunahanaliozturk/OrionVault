namespace Moongazing.OrionVault.Tests;

using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Caching;
using Moongazing.OrionVault.Exceptions;
using Xunit;

public sealed class CachingKeyProviderTests
{
    private static byte[] Key32(byte fill)
    {
        var bytes = new byte[32];
        Array.Fill(bytes, fill);
        return bytes;
    }

    /// <summary>
    /// A deterministic <see cref="TimeProvider"/> whose clock only moves when the test advances it.
    /// Lets the TTL / refresh behaviour be asserted without any real waiting.
    /// </summary>
    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset now;

        public ManualTimeProvider(DateTimeOffset start) => now = start;

        public override DateTimeOffset GetUtcNow() => now;

        public void Advance(TimeSpan by) => now += by;
    }

    /// <summary>
    /// A fake unwrap source that counts how many times it is asked to unwrap and serves a
    /// per-call snapshot, so a refresh can be observed by the key bytes changing.
    /// </summary>
    private sealed class CountingSource : IUnwrappedKeySource
    {
        private readonly Func<int, IReadOnlyDictionary<short, ReadOnlyMemory<byte>>> snapshotForCall;

        public CountingSource(
            short activeKeyId,
            Func<int, IReadOnlyDictionary<short, ReadOnlyMemory<byte>>> snapshotForCall)
        {
            ActiveKeyId = activeKeyId;
            this.snapshotForCall = snapshotForCall;
        }

        public int Calls { get; private set; }

        public short ActiveKeyId { get; }

        public Func<int, Exception?>? ThrowOnCall { get; set; }

        public Task<IReadOnlyDictionary<short, ReadOnlyMemory<byte>>> UnwrapAllAsync(
            CancellationToken cancellationToken)
        {
            Calls++;
            var ex = ThrowOnCall?.Invoke(Calls);
            if (ex is not null)
            {
                return Task.FromException<IReadOnlyDictionary<short, ReadOnlyMemory<byte>>>(ex);
            }
            return Task.FromResult(snapshotForCall(Calls));
        }
    }

    private static EnvelopeKeyCacheOptions Enabled(TimeSpan ttl, bool serveStale = true)
        => new() { Enabled = true, Ttl = ttl, ServeStaleOnRefreshFailure = serveStale };

    [Fact]
    public void Constructor_throws_when_caching_disabled()
    {
        var source = new CountingSource(1, _ => new Dictionary<short, ReadOnlyMemory<byte>> { [1] = Key32(0x11) });
        var ex = Assert.Throws<OrionVaultConfigurationException>(
            () => new CachingKeyProvider(source, new EnvelopeKeyCacheOptions { Enabled = false }));
        Assert.Contains("disabled", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Constructor_throws_when_ttl_not_positive()
    {
        var source = new CountingSource(1, _ => new Dictionary<short, ReadOnlyMemory<byte>> { [1] = Key32(0x11) });
        Assert.Throws<OrionVaultConfigurationException>(
            () => new CachingKeyProvider(source, new EnvelopeKeyCacheOptions { Enabled = true, Ttl = TimeSpan.Zero }));
    }

    [Fact]
    public void Unwraps_once_then_serves_repeated_lookups_from_cache_within_ttl()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var source = new CountingSource(1, _ => new Dictionary<short, ReadOnlyMemory<byte>> { [1] = Key32(0x11) });
        using var sut = new CachingKeyProvider(source, Enabled(TimeSpan.FromMinutes(15)), time);

        // First lookup primes the cache (one unwrap). Subsequent lookups inside the TTL must not
        // unwrap again.
        for (var i = 0; i < 10; i++)
        {
            var key = sut.TryGetKey(1);
            Assert.NotNull(key);
            Assert.True(Key32(0x11).AsSpan().SequenceEqual(key!.Value.Span));
        }

        // Advance, but stay strictly under the TTL.
        time.Advance(TimeSpan.FromMinutes(14));
        Assert.NotNull(sut.TryGetKey(1));

        Assert.Equal(1, source.Calls);
    }

    [Fact]
    public void Refreshes_after_ttl_elapses_and_picks_up_rotated_key()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        // Call 1 -> key 0x11; call 2 (after refresh) -> key 0x22 (simulates a KMS-side rotation).
        var source = new CountingSource(1, call => new Dictionary<short, ReadOnlyMemory<byte>>
        {
            [1] = call == 1 ? Key32(0x11) : Key32(0x22),
        });
        using var sut = new CachingKeyProvider(source, Enabled(TimeSpan.FromMinutes(15)), time);

        Assert.True(Key32(0x11).AsSpan().SequenceEqual(sut.TryGetKey(1)!.Value.Span));
        Assert.Equal(1, source.Calls);

        // Cross the TTL boundary exactly: expiry is >= ttl, so 15 minutes is expired.
        time.Advance(TimeSpan.FromMinutes(15));

        var afterRefresh = sut.TryGetKey(1);
        Assert.True(Key32(0x22).AsSpan().SequenceEqual(afterRefresh!.Value.Span));
        Assert.Equal(2, source.Calls);
    }

    [Fact]
    public void Does_not_refresh_again_until_a_second_ttl_window_elapses()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var source = new CountingSource(1, _ => new Dictionary<short, ReadOnlyMemory<byte>> { [1] = Key32(0x11) });
        using var sut = new CachingKeyProvider(source, Enabled(TimeSpan.FromMinutes(15)), time);

        sut.TryGetKey(1);                       // call 1 (prime)
        time.Advance(TimeSpan.FromMinutes(15));
        sut.TryGetKey(1);                       // call 2 (refresh)
        time.Advance(TimeSpan.FromMinutes(5));  // still inside the new window
        sut.TryGetKey(1);                       // served from cache
        Assert.Equal(2, source.Calls);

        time.Advance(TimeSpan.FromMinutes(10)); // now 15 min since the refresh -> expired again
        sut.TryGetKey(1);                       // call 3
        Assert.Equal(3, source.Calls);
    }

    [Fact]
    public void Prime_unwraps_eagerly_so_misconfiguration_surfaces_at_startup()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        // active id 2 but the source never returns id 2 -> Validate must throw on Prime.
        var source = new CountingSource(2, _ => new Dictionary<short, ReadOnlyMemory<byte>> { [1] = Key32(0x11) });
        using var sut = new CachingKeyProvider(source, Enabled(TimeSpan.FromMinutes(15)), time);

        var ex = Assert.Throws<OrionVaultConfigurationException>(() => sut.Prime());
        Assert.Contains("active key id 2", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Rejects_wrong_length_key_from_source()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var source = new CountingSource(1, _ => new Dictionary<short, ReadOnlyMemory<byte>> { [1] = new byte[16] });
        using var sut = new CachingKeyProvider(source, Enabled(TimeSpan.FromMinutes(15)), time);

        var ex = Assert.Throws<OrionVaultConfigurationException>(() => sut.TryGetKey(1));
        Assert.Contains("32", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Serves_stale_snapshot_when_refresh_fails_and_policy_allows()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var source = new CountingSource(1, _ => new Dictionary<short, ReadOnlyMemory<byte>> { [1] = Key32(0x11) })
        {
            // First unwrap succeeds; the refresh (call 2) throws.
            ThrowOnCall = call => call >= 2 ? new InvalidOperationException("KMS down") : null,
        };
        using var sut = new CachingKeyProvider(source, Enabled(TimeSpan.FromMinutes(15), serveStale: true), time);

        Assert.True(Key32(0x11).AsSpan().SequenceEqual(sut.TryGetKey(1)!.Value.Span));

        time.Advance(TimeSpan.FromMinutes(20)); // expire -> refresh attempt fails

        // Still serves the last-good snapshot rather than throwing.
        Assert.True(Key32(0x11).AsSpan().SequenceEqual(sut.TryGetKey(1)!.Value.Span));
        Assert.True(source.Calls >= 2); // it did attempt the refresh
    }

    [Fact]
    public void Fails_closed_on_refresh_failure_when_serve_stale_disabled()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var source = new CountingSource(1, _ => new Dictionary<short, ReadOnlyMemory<byte>> { [1] = Key32(0x11) })
        {
            ThrowOnCall = call => call >= 2 ? new InvalidOperationException("KMS down") : null,
        };
        using var sut = new CachingKeyProvider(source, Enabled(TimeSpan.FromMinutes(15), serveStale: false), time);

        sut.TryGetKey(1); // prime ok
        time.Advance(TimeSpan.FromMinutes(20));

        Assert.Throws<InvalidOperationException>(() => sut.TryGetKey(1));
    }

    [Fact]
    public void First_unwrap_failure_always_propagates_regardless_of_stale_policy()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var source = new CountingSource(1, _ => new Dictionary<short, ReadOnlyMemory<byte>> { [1] = Key32(0x11) })
        {
            ThrowOnCall = _ => new InvalidOperationException("KMS down on first contact"),
        };
        // serveStale is true, but there is no previous snapshot to fall back to.
        using var sut = new CachingKeyProvider(source, Enabled(TimeSpan.FromMinutes(15), serveStale: true), time);

        Assert.Throws<InvalidOperationException>(() => sut.TryGetKey(1));
    }

    [Fact]
    public void ActiveKeyId_is_exposed_without_unwrapping()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var source = new CountingSource(7, _ => new Dictionary<short, ReadOnlyMemory<byte>> { [7] = Key32(0x77) });
        using var sut = new CachingKeyProvider(source, Enabled(TimeSpan.FromMinutes(15)), time);

        Assert.Equal(7, sut.ActiveKeyId);
        Assert.Equal(0, source.Calls); // reading ActiveKeyId must not trigger an unwrap
    }

    [Fact]
    public void Concurrent_cold_lookups_unwrap_exactly_once()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UnixEpoch);
        var source = new CountingSource(1, _ => new Dictionary<short, ReadOnlyMemory<byte>> { [1] = Key32(0x11) });
        using var sut = new CachingKeyProvider(source, Enabled(TimeSpan.FromMinutes(15)), time);

        // A burst of concurrent first-lookups must collapse to a single unwrap (single-flight).
        Parallel.For(0, 64, _ =>
        {
            var key = sut.TryGetKey(1);
            Assert.NotNull(key);
        });

        Assert.Equal(1, source.Calls);
    }
}
