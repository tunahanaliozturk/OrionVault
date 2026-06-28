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
/// <item>Single-flight: a <see cref="SemaphoreSlim"/> serialises refreshes so a burst of stale
/// reads triggers exactly one KMS round-trip, not one per caller. While a refresh is in flight,
/// other callers that already hold a (stale) snapshot keep serving it.</item>
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
        var snapshot = current;
        if (snapshot is not null && !IsExpired(snapshot))
        {
            return snapshot;
        }

        // Either no snapshot yet (cold) or the held one is stale. Serialise the refresh so only
        // one caller round-trips the KMS; the rest re-read the freshly published snapshot.
        refreshGate.Wait();
        try
        {
            // Re-check under the gate: another caller may have refreshed while we waited.
            snapshot = current;
            if (snapshot is not null && !IsExpired(snapshot))
            {
                return snapshot;
            }

            return Refresh(previous: snapshot);
        }
        finally
        {
            refreshGate.Release();
        }
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
        catch (Exception ex) when (previous is not null && serveStaleOnRefreshFailure)
        {
            // Keep serving the previous snapshot through a transient KMS failure, but do not
            // reset its timestamp: the next lookup will attempt another refresh. We deliberately
            // do not rethrow. The exception detail is intentionally not swallowed silently in
            // production wiring, where an IKeyRotationObserver / logging adapter can be layered;
            // here, failing open to the last-good keys is the documented policy.
            _ = ex;
            return previous;
        }

        var validated = Validate(unwrapped);
        var fresh = new Snapshot(validated, timeProvider.GetUtcNow());
        current = fresh;
        return fresh;
    }

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
