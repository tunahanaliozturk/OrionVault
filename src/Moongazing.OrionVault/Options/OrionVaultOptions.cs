namespace Moongazing.OrionVault.Options;

using Moongazing.OrionVault.BlindIndex;

public sealed class OrionVaultOptions
{
    private StaticKeysBuilder? _keys;
    private BlindIndexKeysBuilder? _blindIndexKeys;

    public short ActiveKeyId { get; set; }

    public void UseStaticKeys(Action<StaticKeysBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        _keys ??= new StaticKeysBuilder();
        configure(_keys);
    }

    /// <summary>
    /// The blind index key version used for all new searchable-index writes. Only consulted
    /// when <see cref="UseBlindIndex"/> has registered at least one index key. Defaults to 0.
    /// </summary>
    public short ActiveBlindIndexVersion { get; set; }

    /// <summary>
    /// How values are normalized before being hashed into a blind index. Must stay constant
    /// for a given index; changing it is a re-index operation.
    /// </summary>
    public BlindIndexNormalization BlindIndexNormalization { get; set; }
        = BlindIndexNormalization.TrimAndLowercaseInvariant;

    /// <summary>
    /// Registers the versioned HMAC keys backing searchable encryption (the blind index).
    /// Calling this opts the host into resolving an <see cref="Abstractions.IBlindIndexProvider"/>
    /// from DI. Index keys are independent from the encryption keys configured via
    /// <see cref="UseStaticKeys"/> and must use different secret material.
    /// </summary>
    public void UseBlindIndex(Action<BlindIndexKeysBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        _blindIndexKeys ??= new BlindIndexKeysBuilder();
        configure(_blindIndexKeys);
    }

    internal StaticKeysBuilder? KeysBuilder => _keys;

    internal BlindIndexKeysBuilder? BlindIndexKeysBuilder => _blindIndexKeys;
}
