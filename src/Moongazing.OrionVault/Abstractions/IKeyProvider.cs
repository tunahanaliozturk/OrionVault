namespace Moongazing.OrionVault.Abstractions;

/// <summary>
/// Provides 256-bit symmetric keys identified by a short key id. Implementations
/// must be thread-safe and registered as singletons. v0.1.0 ships
/// <c>StaticKeyProvider</c> (in-config base64 keys); v0.2 roadmap adds AWS KMS,
/// Azure Key Vault, and Windows DPAPI providers.
/// </summary>
public interface IKeyProvider
{
    /// <summary>
    /// The key id used for all new encryptions. Must be registered (i.e.,
    /// <see cref="TryGetKey"/>(<see cref="ActiveKeyId"/>) returns non-null).
    /// </summary>
    short ActiveKeyId { get; }

    /// <summary>
    /// Looks up a key by id. Returns <c>null</c> if the id is not registered.
    /// The returned memory must be exactly 32 bytes.
    /// </summary>
    ReadOnlyMemory<byte>? TryGetKey(short keyId);

    /// <summary>
    /// v0.2.25: number of registered keys, or <c>-1</c> when the provider cannot
    /// enumerate (remote KMS-style providers). Default interface implementation
    /// returns <c>-1</c> so existing custom providers compile unchanged. Feeds the
    /// <c>orionvault.keys.registered_count</c> gauge.
    /// </summary>
    int KeyCount => -1;
}
