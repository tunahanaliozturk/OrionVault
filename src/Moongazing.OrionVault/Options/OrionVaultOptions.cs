namespace Moongazing.OrionVault.Options;

public sealed class OrionVaultOptions
{
    private StaticKeysBuilder? _keys;

    public short ActiveKeyId { get; set; }

    public void UseStaticKeys(Action<StaticKeysBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        _keys ??= new StaticKeysBuilder();
        configure(_keys);
    }

    internal StaticKeysBuilder? KeysBuilder => _keys;
}
