# Moongazing.OrionVault.GcpKms

Google Cloud KMS-backed key provider for OrionVault. Wraps OrionVault's 32-byte symmetric data keys with a Cloud KMS crypto key via envelope encryption.

## How it works

OrionVault stores wrapped (KMS-ciphertext) data keys in your application config or secret store. At host startup the provider calls `KeyManagementServiceClient.Decrypt` against Cloud KMS to recover each plaintext data key, then keeps those plaintext keys in process memory for the lifetime of the provider. The crypto key itself never leaves Google Cloud.

## Install

```bash
dotnet add package OrionVault.GcpKms
```

## Wire-up

```csharp
services.AddSingleton(KeyManagementServiceClient.Create());

services.AddOrionVaultGcpKms(o =>
{
    o.CryptoKeyName = "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/orionvault";
    o.ActiveKeyId = 1;
    o.WrappedKeys[1] = "BASE64-KMS-CIPHERTEXT-FOR-KEY-1";
    o.WrappedKeys[2] = "BASE64-KMS-CIPHERTEXT-FOR-KEY-2";
});

services.AddOrionVault(/* ... */);
```

`ActiveKeyId` is used for new encryptions; previously-active ids stay resolvable so existing rows continue to decrypt during a rotation rollout (the standard OrionVault multi-key read, single-key write pattern).

## Envelope-key caching (opt-in)

By default the provider unwraps once at startup and holds the plaintext keys for the provider lifetime. Enable the v0.4.0 envelope-key cache to re-fetch the wrapped keys on a TTL so a Cloud KMS key disabled / rotated mid-run is picked up without a host restart:

```csharp
services.AddOrionVaultGcpKms(o =>
{
    o.CryptoKeyName = "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/orionvault";
    o.ActiveKeyId = 1;
    o.WrappedKeys[1] = "BASE64-KMS-CIPHERTEXT-FOR-KEY-1";

    o.Cache.Enabled = true;
    o.Cache.Ttl = TimeSpan.FromMinutes(10);
});
```
