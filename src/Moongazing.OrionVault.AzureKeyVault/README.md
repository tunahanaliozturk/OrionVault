# Moongazing.OrionVault.AzureKeyVault

Azure Key Vault-backed key provider for OrionVault. Wraps OrionVault's 32-byte symmetric data keys with an Azure Key Vault KEK (RSA-OAEP-256 by default, or AES-KW for HSM-backed AES keys).

## How it works

You store wrapped (KEK-ciphertext) data keys in your application config or secret store. At host startup the provider calls `KeyClient.GetCryptographyClient(keyName).UnwrapKey(...)` against Azure Key Vault to recover each plaintext data key, then keeps those plaintext data keys in process memory for the lifetime of the provider. The KEK itself never leaves Azure Key Vault.

## Install

```bash
dotnet add package OrionVault.AzureKeyVault
```

## Wire-up

```csharp
services.AddSingleton(new KeyClient(
    new Uri("https://my-vault.vault.azure.net/"),
    new DefaultAzureCredential()));

services.AddOrionVaultAzureKeyVault(o =>
{
    o.KeyName = "orionvault-kek";
    o.ActiveKeyId = 1;
    o.WrappedKeys[1] = "BASE64-AZURE-WRAPPED-DATA-KEY-1";
    o.WrappedKeys[2] = "BASE64-AZURE-WRAPPED-DATA-KEY-2";
});

services.AddOrionVault(/* ... */);
```

`ActiveKeyId` is used for new encryptions; previously-active ids stay resolvable so existing rows continue to decrypt during rotation rollouts (the standard OrionVault multi-key read, single-key write pattern).

## Configuration

| Property | Default | Notes |
|---|---|---|
| `KeyName` | required | Vault key name (or full key identifier) used for unwrap. |
| `KeyVersion` | latest | Specify when pinning to a specific KEK version. |
| `WrapAlgorithm` | `RsaOaep256` | Azure `KeyWrapAlgorithm` to use during unwrap. Use `A256KW` for HSM-backed AES keys. |
| `ActiveKeyId` | required | Active data-key id used for new encryptions. |
| `WrappedKeys` | required | Map of `short` -> base64 wrapped data key. |
