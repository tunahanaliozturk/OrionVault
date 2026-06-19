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

    // Blind index HMAC keys. Independent from the AES keys above: the blind index trades a
    // little confidentiality (equal values become linkable) for searchability, so its key
    // must be different secret material. 32 bytes, base64-encoded. Two versions so the demo
    // can show an index key rotation. All 0x22 bytes for v1, all 0x33 bytes for v2.
    public const string BlindIndexKeyV1 = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=";
    public const string BlindIndexKeyV2 = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=";

    public const short BlindIndexVersionV1 = 1;
    public const short BlindIndexVersionV2 = 2;
}
