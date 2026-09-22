namespace Moongazing.OrionVault.Caching;

using System.Collections.Frozen;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Exceptions;

/// <summary>
/// An <see cref="IKeyProvider"/> that unwraps its data keys through an
/// <see cref="IUnwrappedKeySource"/> and caches the result for a configurable TTL, refreshing the
/// snapshot once it has expired. This is the v0.4.0 envelope-key cache: instead of pinning the
/// startup-unwrapped plaintext keys for the process lifetime, a long-running host re-fetches the
/// wrapped keys after the TTL so a data key disabled / revoked / rotated at the KMS is honoured
/// without a restart.
/// </summary>
/// <remarks>
/// Thread-safety and bounding:
/// <list type="bullet">
/// <item>Exactly one unwrapped snapshot is held at a time (bounded: O(number of configured keys)).
/// A refresh builds a new immutable <see cref="FrozenDictionary{TKey,TValue}"/> and swaps the
/// volatile reference atomically; readers never observe a half-built map.</item>
/// <item>Single-flight, non-blocking reads: a <see cref="SemaphoreSlim"/> serialises refreshes so a
/// burst of stale reads triggers exactly one KMS round-trip, not one per caller. Crucially, a
/// reader that already holds a (stale) snapshot does NOT queue behind the in-flight refresh: it
/// fails the non-blocking gate acquisition and serves the current snapshot immediately. Only the
/// single thread that wins the gate waits on the KMS round-trip; everyone else keeps serving the
/// last-good keys until that thread publishes the fresh snapshot. The sole blocking path is the
/// cold start (no snapshot yet), where callers must wait for the very first unwrap.</item>
/// <item>Failure policy: a transient refresh failure with a snapshot in hand keeps serving the
/// stale snapshot when <see cref="EnvelopeKeyCacheOptions.ServeStaleOnRefreshFailure"/> is set; a
/// revocation-class failure (key disabled / revoked / not-found / access withdrawn, surfaced as a
/// <see cref="KeyUnwrapException"/> of kind <see cref="KeyUnwrapFailureKind.Revocation"/>) always
/// fails closed regardless of that flag.</item>
/// <item>A revocation LATCHES. Failing only the caller that happened to win the refresh gate
/// would leave every concurrent and subsequent caller decrypting with the revoked key, and the
/// race would repeat on each expiry for as long as traffic lasts. Once a refresh has established
/// a revocation the snapshot is dropped and every later caller fails closed immediately, without
/// a KMS round-trip. The latch clears by itself: one caller at a time re-probes, no more often
/// than the TTL, so an operator who re-enables the key gets service back within a TTL rather than
/// needing a process restart. See <see cref="EnsureFresh"/> for the one window this does not
/// close.</item>
/// <item>Time is read through an injected <see cref="System.TimeProvider"/> so TTL expiry is
/// deterministic under test.</item>
/// </list>
/// The provider is registered as a singleton (like every <see cref="IKeyProvider"/>); the unwrap
/// happens lazily on first lookup unless <see cref="Prime"/> is called at startup.
/// </remarks>
public sealed class CachingKeyProvider : IKeyProvider, IDisposable
{
    private readonly IUnwrappedKeySource source;
    private readonly TimeSpan ttl;
    private readonly bool serveStaleOnRefreshFailure;
    private readonly TimeProvider timeProvider;
    private readonly SemaphoreSlim refreshGate = new(1, 1);

    // Read on every TryGetKey; written only under refreshGate. volatile so the swap publishes.
    private volatile Snapshot? current;

    // Set once a refresh has established that the key is revoked; cleared by a later successful
    // unwrap. Read on every TryGetKey, written only under refreshGate. volatile so the latch
    // publishes to racing readers as soon as the refreshing thread sets it.
    private volatile Denial? denial;

    /// <summary>
    /// Constructs a caching provider over the supplied <paramref name="source"/>.
    /// </summary>
    /// <param name="source">The unwrap operation to drive on each refresh.</param>
    /// <param name="options">TTL and stale-serve policy. <see cref="EnvelopeKeyCacheOptions.Validate"/>
    /// is applied; an invalid combination throws <see cref="OrionVaultConfigurationException"/>.</param>
    /// <param name="timeProvider">Clock used for TTL expiry; defaults to
    /// <see cref="TimeProvider.System"/>. Tests pass a controllable provider.</param>
    public CachingKeyProvider(
        IUnwrappedKeySource source,
        EnvelopeKeyCacheOptions options,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        if (!options.Enabled)
        {
            throw new OrionVaultConfigurationException(
                "CachingKeyProvider was constructed with caching disabled. Use the provider's " +
                "unwrap-once path instead, or set EnvelopeKeyCacheOptions.Enabled = true.");
        }

        this.source = source;
        ttl = options.Ttl;
        serveStaleOnRefreshFailure = options.ServeStaleOnRefreshFailure;
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public short ActiveKeyId => source.ActiveKeyId;

    /// <inheritdoc />
    public int KeyCount => current?.Keys.Count ?? -1;

    /// <summary>
    /// Forces the first unwrap up front (at host startup) so the initial KMS round-trip and any
    /// misconfiguration surface during composition rather than on the first decrypt. Optional:
    /// if not called, the first <see cref="TryGetKey"/> primes the cache lazily.
    /// </summary>
    public void Prime() => EnsureFresh();

    /// <inheritdoc />
    public ReadOnlyMemory<byte>? TryGetKey(short keyId)
    {
        var snapshot = EnsureFresh();
        return snapshot.Keys.TryGetValue(keyId, out var key) ? key : null;
    }

    private Snapshot EnsureFresh()
    {
        // Checked before the snapshot: once a revocation is latched nobody is served a cached key
        // again, whether or not they hold one and whoever wins the gate. Costs one volatile read
        // on the hot path.
        var latched = denial;
        if (latched is not null)
        {
            return RetryAfterRevocation(latched);
        }

        var snapshot = current;
        if (snapshot is not null && !IsExpired(snapshot))
        {
            return snapshot;
        }

        // The held snapshot is stale (or there is none yet). Single-flight the refresh.
        if (snapshot is not null)
        {
            // We already have a (stale) snapshot to fall back on, so DO NOT block behind an
            // in-flight refresh. Try to win the gate without waiting: if another caller is already
            // refreshing, serve the current snapshot immediately instead of queueing.
            if (!refreshGate.Wait(0))
            {
                // Re-read the latch: the in-flight refresh may have established a revocation
                // between the check at the top of this method and here. This does not close the
                // window entirely - a caller that loses the gate while the very first
                // revocation-reporting refresh is still awaiting the KMS is served the stale key,
                // because nothing yet knows the key is revoked. That window is one KMS round-trip
                // and happens once: the latch it then sets stops every caller after it, so the
                // race cannot repeat on each expiry for as long as traffic lasts. Closing it
                // outright would mean blocking every reader on a network call once per TTL, which
                // is the thread-pool starvation this non-blocking gate exists to avoid.
                latched = denial;
                if (latched is not null)
                {
                    return RetryAfterRevocation(latched);
                }

                return current ?? snapshot;
            }

            try
            {
                // Re-check under the gate: another caller may have refreshed while we waited.
                var latest = current;
                if (latest is not null && !IsExpired(latest))
                {
                    return latest;
                }

                return Refresh(previous: latest);
            }
            finally
            {
                refreshGate.Release();
            }
        }

        // Cold start: no snapshot to serve, so callers must wait for the first unwrap.
        refreshGate.Wait();
        try
        {
            var latest = current;
            if (latest is not null && !IsExpired(latest))
            {
                return latest;
            }

            return Refresh(previous: latest);
        }
        finally
        {
            refreshGate.Release();
        }
    }

    // A revocation is latched. Everyone fails closed; one caller at a time, and no more often than
    // the TTL, re-probes the KMS so the latch can clear without a process restart.
    private Snapshot RetryAfterRevocation(Denial latched)
    {
        if (timeProvider.GetUtcNow() - latched.LatchedAtUtc >= ttl && refreshGate.Wait(0))
        {
            try
            {
                // Another caller may have re-probed successfully while we were getting here.
                if (denial is null && current is { } recovered && !IsExpired(recovered))
                {
                    return recovered;
                }

                // previous: null - there is deliberately nothing to serve stale from. A probe
                // that fails again (for any reason) leaves the latch standing and throws.
                return Refresh(previous: null);
            }
            finally
            {
                refreshGate.Release();
            }
        }

        throw new KeyUnwrapException(
            KeyUnwrapFailureKind.Revocation,
            "CachingKeyProvider: the backing KMS reported this key as revoked (disabled / deleted / " +
            "access withdrawn), so the cached data keys were dropped and every lookup fails closed. " +
            $"The unwrap is retried at most once per cache TTL ({ttl}); re-enabling the key or " +
            "restoring access clears this automatically on the next successful unwrap. " +
            $"Original failure: {latched.Cause.Message}",
            latched.Cause);
    }

    // Called holding refreshGate.
    private Snapshot Refresh(Snapshot? previous)
    {
        IReadOnlyDictionary<short, ReadOnlyMemory<byte>> unwrapped;
        try
        {
            // The unwrap is async and network-bound; IKeyProvider.TryGetKey is a sync contract,
            // so we block here exactly as the unwrap-once startup path already does. The single-
            // flight gate guarantees only one such blocking call is outstanding at a time.
            unwrapped = source.UnwrapAllAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
        catch (Exception ex) when (CanServeStale(previous, ex))
        {
            // Keep serving the previous snapshot through a TRANSIENT KMS failure, but do not
            // reset its timestamp: the next lookup will attempt another refresh. We deliberately
            // do not rethrow. The exception detail is intentionally not swallowed silently in
            // production wiring, where an IKeyRotationObserver / logging adapter can be layered;
            // here, failing open to the last-good keys is the documented policy for transient
            // faults. A revocation-class failure is excluded by CanServeStale and propagates,
            // so a disabled / revoked / withdrawn key stops decrypting immediately.
            _ = ex;
            return previous!;
        }
        catch (Exception ex) when (IsRevocation(ex))
        {
            // Latch before rethrowing, and drop the snapshot with it. Without this only the caller
            // holding the gate would fail while every racing and subsequent caller kept being
            // served the cached plaintext of a key the KMS has explicitly stopped honouring.
            denial = new Denial(ex, timeProvider.GetUtcNow());
            current = null;
            throw;
        }

        var validated = Validate(unwrapped);
        var fresh = new Snapshot(validated, timeProvider.GetUtcNow());
        current = fresh;
        // A successful unwrap is the authoritative signal that access is back; clear the latch.
        denial = null;
        return fresh;
    }

    // Stale serving is allowed only when we have a previous snapshot, the policy permits it, and
    // the failure is NOT a revocation-class denial. A revoked / disabled / not-found / access-
    // withdrawn key must fail closed: serving the cached plaintext past an explicit KMS denial
    // would let a key keep decrypting after it was meant to stop.
    private bool CanServeStale(Snapshot? previous, Exception ex)
    {
        if (previous is null || !serveStaleOnRefreshFailure)
        {
            return false;
        }

        return !IsRevocation(ex);
    }

    private static bool IsRevocation(Exception ex)
        => ex is KeyUnwrapException { Kind: KeyUnwrapFailureKind.Revocation };

    private FrozenDictionary<short, ReadOnlyMemory<byte>> Validate(
        IReadOnlyDictionary<short, ReadOnlyMemory<byte>> unwrapped)
    {
        if (unwrapped is null || unwrapped.Count == 0)
        {
            throw new OrionVaultConfigurationException(
                "CachingKeyProvider: the unwrapped key source returned no keys.");
        }
        foreach (var (id, key) in unwrapped)
        {
            if (key.Length != 32)
            {
                throw new OrionVaultConfigurationException(
                    $"CachingKeyProvider: key id {id} length is {key.Length} bytes; OrionVault requires exactly 32.");
            }
        }
        if (!unwrapped.ContainsKey(source.ActiveKeyId))
        {
            throw new OrionVaultConfigurationException(
                $"CachingKeyProvider: active key id {source.ActiveKeyId} is not in the unwrapped key map. " +
                $"Returned ids: [{string.Join(", ", unwrapped.Keys)}].");
        }
        return unwrapped.ToFrozenDictionary();
    }

    private bool IsExpired(Snapshot snapshot)
        => timeProvider.GetUtcNow() - snapshot.UnwrappedAtUtc >= ttl;

    /// <inheritdoc />
    public void Dispose() => refreshGate.Dispose();

    // A latched revocation: the failure that established it, and when, so the re-probe can be
    // rate-limited to the TTL instead of hammering the KMS once per lookup.
    private sealed class Denial
    {
        public Denial(Exception cause, DateTimeOffset latchedAtUtc)
        {
            Cause = cause;
            LatchedAtUtc = latchedAtUtc;
        }

        public Exception Cause { get; }

        public DateTimeOffset LatchedAtUtc { get; }
    }

    private sealed class Snapshot
    {
        public Snapshot(FrozenDictionary<short, ReadOnlyMemory<byte>> keys, DateTimeOffset unwrappedAtUtc)
        {
            Keys = keys;
            UnwrappedAtUtc = unwrappedAtUtc;
        }

        public FrozenDictionary<short, ReadOnlyMemory<byte>> Keys { get; }

        public DateTimeOffset UnwrappedAtUtc { get; }
    }
}
