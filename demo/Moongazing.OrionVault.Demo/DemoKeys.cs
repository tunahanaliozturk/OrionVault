namespace Moongazing.OrionVault.Demo;

/// <summary>
/// Deterministic in-memory AES-256 keys used across the demos. These are 32-byte
/// (256-bit) base64-encoded keys generated once and hard-coded so the demo is
/// reproducible. NEVER ship hard-coded keys like this in production; load them from a
/// secret store (env var, KMS, Key Vault) instead.
/// </summary>
internal static class DemoKeys
{
    // 32 zero bytes. Valid 256-bit key, fine for a local demo only.
    public const string KeyV1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    // A second, distinct 32-byte key for the rotation demo (all 0x11 bytes).
    public const string KeyV2 = "ERERERERERERERERERERERERERERERERERERERERERE=";

    public const short KeyIdV1 = 1;
    public const short KeyIdV2 = 2;
}
