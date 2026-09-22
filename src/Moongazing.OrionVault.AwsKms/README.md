# Moongazing.OrionVault.AwsKms

AWS KMS-backed key provider for OrionVault. Wraps OrionVault's 32-byte symmetric data keys with an AWS KMS customer master key (CMK) via envelope encryption.

## How it works

OrionVault stores wrapped (KMS-ciphertext) data keys in your application config or secret store. At host startup the provider calls `KeyManagementService.Decrypt` against AWS KMS to recover each plaintext data key, then keeps those plaintext keys in process memory for the lifetime of the provider. The CMK itself never leaves AWS.

Every decrypt is pinned to `KeyId` (`DecryptRequest.KeyId`). Without that, KMS resolves the CMK from the ciphertext blob's own metadata, so anyone who can influence `WrappedKeys` — a config store, an environment variable, an `appsettings.json` baked into a container image, a compromised deploy pipeline — could substitute a data key they wrapped under a CMK *they* control that your principal happens to hold `kms:Decrypt` on, and it would silently become OrionVault's active key. `KeyId` is therefore required.

## Install

```bash
dotnet add package OrionVault.AwsKms
```

## Wire-up

```csharp
services.AddAWSService<IAmazonKeyManagementService>();

services.AddOrionVaultAwsKms(o =>
{
    o.KeyId = "arn:aws:kms:us-east-1:111122223333:key/abcd1234-ab12-cd34-ef56-abcdef123456";
    o.ActiveKeyId = 1;
    o.WrappedKeys[1] = "BASE64-KMS-CIPHERTEXT-FOR-KEY-1";
    o.WrappedKeys[2] = "BASE64-KMS-CIPHERTEXT-FOR-KEY-2";
});

services.AddOrionVault(/* ... */);
```

`ActiveKeyId` is used for new encryptions; previously-active ids stay resolvable so existing rows continue to decrypt during a rotation rollout (the standard OrionVault multi-key read, single-key write pattern).

## Configuration

| Property | Default | Notes |
|---|---|---|
| `KeyId` | required | The CMK every wrapped key must decrypt under: key id, key ARN, alias name (`alias/orionvault`) or alias ARN. Passed as `DecryptRequest.KeyId`. |
| `ActiveKeyId` | required | Active data-key id used for new encryptions. |
| `WrappedKeys` | required | Map of `short` -> base64 KMS ciphertext blob. |
| `Cache` | off | Opt-in envelope-key cache; see below. |

## Envelope-key caching (opt-in)

By default the provider unwraps once at startup and holds the plaintext keys for the provider lifetime — which means a CMK disabled or scheduled for deletion mid-run keeps working until the host restarts. Enable the envelope-key cache to re-fetch the wrapped keys on a TTL so a revoked CMK is honoured without a restart:

```csharp
services.AddOrionVaultAwsKms(o =>
{
    o.KeyId = "arn:aws:kms:us-east-1:111122223333:key/abcd1234-ab12-cd34-ef56-abcdef123456";
    o.ActiveKeyId = 1;
    o.WrappedKeys[1] = "BASE64-KMS-CIPHERTEXT-FOR-KEY-1";

    o.Cache.Enabled = true;
    o.Cache.Ttl = TimeSpan.FromMinutes(10);
});
```

A refresh that hits a revocation-class denial — `KMSInvalidStateException`, `DisabledException`, `NotFoundException`, `AccessDenied`, or a blob the pinned CMK will not decrypt — fails closed even with `Cache.ServeStaleOnRefreshFailure` left on. Throttling, `KMSInternalException`, dependency timeouts and 5xx are treated as transient and keep serving the last-good snapshot.
