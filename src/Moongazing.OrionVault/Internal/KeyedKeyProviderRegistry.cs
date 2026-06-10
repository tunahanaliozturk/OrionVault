namespace Moongazing.OrionVault.Internal;

using System.Collections.Concurrent;
using Moongazing.OrionVault.Abstractions;

/// <summary>
/// Default <see cref="IKeyedKeyProviderRegistry"/> backed by a
/// <see cref="ConcurrentDictionary{TKey, TValue}"/>. Registration order is preserved via
/// a side-list keyed under the same names so <see cref="RegisteredNames"/> returns a
/// stable, deterministic order.
/// </summary>
public sealed class KeyedKeyProviderRegistry : IKeyedKeyProviderRegistry
{
    private readonly ConcurrentDictionary<string, IKeyProvider> entries = new(StringComparer.Ordinal);
    private readonly List<string> registrationOrder = new();
    private readonly object orderLock = new();

    /// <summary>
    /// Register <paramref name="provider"/> under <paramref name="name"/>. Idempotent:
    /// the first registration for a given name wins and subsequent calls are no-ops.
    /// Returns <see langword="true"/> when this call performed the registration.
    /// </summary>
    public bool Register(string name, IKeyProvider provider)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(provider);
        if (!entries.TryAdd(name, provider))
        {
            return false;
        }
        lock (orderLock)
        {
            registrationOrder.Add(name);
        }
        return true;
    }

    /// <inheritdoc />
    public IKeyProvider GetProvider(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (!entries.TryGetValue(name, out var provider))
        {
            throw new KeyNotFoundException(
                $"KeyedKeyProviderRegistry: no provider registered under name '{name}'. " +
                $"Registered names: [{string.Join(", ", registrationOrder)}].");
        }
        return provider;
    }

    /// <inheritdoc />
    public bool TryGetProvider(string name, out IKeyProvider? provider)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        var found = entries.TryGetValue(name, out var p);
        provider = p;
        return found;
    }

    /// <inheritdoc />
    public IReadOnlyList<string> RegisteredNames()
    {
        lock (orderLock)
        {
            return registrationOrder.ToArray();
        }
    }

    /// <inheritdoc />
    public bool IsRegistered(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        return entries.ContainsKey(name);
    }
}
