# Moongazing.OrionVault.Testing

Test helpers for OrionVault: `DangerousTestKeyProvider`, `EncryptionAssertions`, and the `AddOrionVaultForTesting()` DI extension.

**Test-only.** Reference this package with `PrivateAssets="all"`. `DangerousTestKeyProvider` serves an all-zero AES key and refuses to construct until the process opts in via `DangerousTestKeyProvider.Enable()` or the `Moongazing.OrionVault.Testing.EnableDangerousTestKeys` AppContext switch; using it raises `OV9000`, which you must suppress explicitly.

For full documentation see https://github.com/tunahanaliozturk/OrionVault.
