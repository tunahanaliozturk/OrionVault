namespace Moongazing.OrionVault;

using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.Internal;

/// <summary>
/// Factory entry point for building an <see cref="IEncryptor"/> bound to a specific
/// <see cref="IKeyProvider"/>. Used by the v0.2.8 per-DbContext binding overload to wire
/// a named provider from <see cref="Abstractions.IKeyedKeyProviderRegistry"/> into a
/// keyed encryptor. The default OrionVault DI registration continues to use the global
/// IKeyProvider; this factory exists for advanced wiring scenarios (multiple key sources
/// in one host) where the consumer needs to construct an encryptor over a non-default
/// provider.
/// </summary>
public static class OrionVaultEncryptor
{
    /// <summary>
    /// Build a new <see cref="IEncryptor"/> over <paramref name="keys"/>. The returned
    /// instance is thread-safe (matches the default registration's contract) and uses
    /// the supplied <paramref name="diagnostics"/> for telemetry. Pass the shared
    /// <see cref="OrionVaultDiagnostics"/> from DI so the keyed encryptor's activity /
    /// counters land on the same telemetry stream as the default one.
    /// </summary>
    public static IEncryptor Create(IKeyProvider keys, OrionVaultDiagnostics diagnostics)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(diagnostics);
        return new AesGcmEncryptor(keys, diagnostics);
    }
}
