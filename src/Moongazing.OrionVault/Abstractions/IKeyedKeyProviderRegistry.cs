namespace Moongazing.OrionVault.Abstractions;

/// <summary>
/// Registry that maps a name (e.g. <c>"primary"</c>, <c>"audit"</c>) to an
/// <see cref="IKeyProvider"/>. Foundation for v0.3.0's per-DbContext provider binding:
/// consumers register multiple providers at startup with distinct names, then a future
/// EF Core integration overload resolves the named provider per DbContext.
/// </summary>
/// <remarks>
/// <para>
/// v0.2.7 ships the registry surface + DI plumbing. The existing default
/// <see cref="IKeyProvider"/> registration continues to work for single-DbContext
/// consumers; the registry is opt-in for the multi-provider scenario.
/// </para>
/// <para>
/// Registry implementations MUST be thread-safe and registered as singletons. Names are
/// compared with <see cref="StringComparer.Ordinal"/> so consumers stay in control of
/// canonicalisation.
/// </para>
/// </remarks>
public interface IKeyedKeyProviderRegistry
{
    /// <summary>
    /// Resolve the provider registered under <paramref name="name"/>. Throws
    /// <see cref="KeyNotFoundException"/> when the name is not registered.
    /// </summary>
    IKeyProvider GetProvider(string name);

    /// <summary>
    /// Try-resolve the provider registered under <paramref name="name"/>. Returns
    /// <see langword="true"/> when found.
    /// </summary>
    bool TryGetProvider(string name, out IKeyProvider? provider);

    /// <summary>Names of all currently registered providers, in registration order.</summary>
    IReadOnlyList<string> RegisteredNames();

    /// <summary>True when <paramref name="name"/> is currently registered.</summary>
    bool IsRegistered(string name);
}
