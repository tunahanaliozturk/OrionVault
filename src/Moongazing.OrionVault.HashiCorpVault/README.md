# Moongazing.OrionVault.HashiCorpVault

HashiCorp Vault-backed key provider for OrionVault. Wraps OrionVault's 32-byte symmetric data keys with a Vault transit-engine key via envelope encryption.

## How it works

OrionVault stores wrapped (transit-ciphertext) data keys in your application config or secret store. A wrapped key is the `vault:v1:...` string the transit `encrypt` endpoint returns. At host startup the provider calls the transit `decrypt` endpoint against Vault to recover each plaintext data key, then keeps those plaintext keys in process memory for the lifetime of the provider. The transit key itself never leaves Vault.

## Install

```bash
dotnet add package OrionVault.HashiCorpVault
```

## Wire-up

```csharp
var authMethod = new TokenAuthMethodInfo("s.my-vault-token");
services.AddSingleton<IVaultClient>(new VaultClient(
    new VaultClientSettings("https://vault.example.com:8200", authMethod)));

services.AddOrionVaultHashiCorpVault(o =>
{
    o.TransitKeyName = "orionvault";
    o.MountPoint = "transit"; // default
    o.ActiveKeyId = 1;
    o.WrappedKeys[1] = "vault:v1:CIPHERTEXT-FOR-KEY-1";
    o.WrappedKeys[2] = "vault:v1:CIPHERTEXT-FOR-KEY-2";
});

services.AddOrionVault(/* ... */);
```

`ActiveKeyId` is used for new encryptions; previously-active ids stay resolvable so existing rows continue to decrypt during a rotation rollout (the standard OrionVault multi-key read, single-key write pattern).

## Envelope-key caching (opt-in)

By default the provider unwraps once at startup and holds the plaintext keys for the provider lifetime. Enable the v0.4.0 envelope-key cache to re-fetch the wrapped keys on a TTL so a transit key rotated / disabled mid-run is picked up without a host restart:

```csharp
services.AddOrionVaultHashiCorpVault(o =>
{
    o.TransitKeyName = "orionvault";
    o.ActiveKeyId = 1;
    o.WrappedKeys[1] = "vault:v1:CIPHERTEXT-FOR-KEY-1";

    o.Cache.Enabled = true;
    o.Cache.Ttl = TimeSpan.FromMinutes(10);
});
```
