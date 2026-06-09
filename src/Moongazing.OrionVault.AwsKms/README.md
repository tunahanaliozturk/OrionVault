# Moongazing.OrionVault.AwsKms

AWS KMS-backed key provider for OrionVault. Wraps OrionVault's 32-byte symmetric data keys with an AWS KMS customer master key (CMK) via envelope encryption.

## How it works

OrionVault stores wrapped (KMS-ciphertext) data keys in your application config or secret store. At host startup the provider calls `KeyManagementService.Decrypt` against AWS KMS to recover each plaintext data key, then keeps those plaintext keys in process memory for the lifetime of the provider. The CMK itself never leaves AWS.

## Install

```bash
dotnet add package OrionVault.AwsKms
```

## Wire-up

```csharp
services.AddAWSService<IAmazonKeyManagementService>();

services.AddOrionVaultAwsKms(o =>
{
    o.ActiveKeyId = 1;
    o.WrappedKeys[1] = "BASE64-KMS-CIPHERTEXT-FOR-KEY-1";
    o.WrappedKeys[2] = "BASE64-KMS-CIPHERTEXT-FOR-KEY-2";
});

services.AddOrionVault(/* ... */);
```

`ActiveKeyId` is used for new encryptions; previously-active ids stay resolvable so existing rows continue to decrypt during a rotation rollout (the standard OrionVault multi-key read, single-key write pattern).
