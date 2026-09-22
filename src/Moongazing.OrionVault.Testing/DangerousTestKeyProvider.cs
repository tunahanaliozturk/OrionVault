namespace Moongazing.OrionVault.Testing;

using System.Collections.Concurrent;
using Moongazing.OrionVault.Abstractions;

/// <summary>
/// Deterministic <see cref="IKeyProvider"/> for tests. The key under the active id is
/// <strong>32 zero bytes</strong> - a publicly known AES key that protects nothing. Every column
/// encrypted under it is readable by anyone who guesses the obvious. Add real keys with
/// <see cref="Add"/>; use <see cref="Default"/> for the common single-key case.
/// <para>
/// This type refuses to construct until the process explicitly opts in - call
/// <see cref="Enable"/> from test setup, or set the <see cref="EnableSwitchName"/> AppContext
/// switch in the test project. That opt-in is what stops a stray
/// <c>AddSingleton&lt;IKeyProvider&gt;(...)</c> or a <c>Testing</c> PackageReference without
/// <c>PrivateAssets</c> from silently protecting production data with a zero key.
/// </para>
/// </summary>
[Obsolete(
    "DangerousTestKeyProvider hands out an all-zero AES key and must never reach a shipped build. " +
    "Suppress OV9000 in the test project to acknowledge that, and reference OrionVault.Testing with PrivateAssets=\"all\".",
    error: false,
    DiagnosticId = "OV9000",
    UrlFormat = "https://github.com/tunahanaliozturk/OrionVault#{0}")]
public sealed class DangerousTestKeyProvider : IKeyProvider
{
    /// <summary>
    /// Name of the AppContext switch that unlocks this type. Set it from the test project with
    /// <c>&lt;RuntimeHostConfigurationOption Include="Moongazing.OrionVault.Testing.EnableDangerousTestKeys" Value="true" /&gt;</c>,
    /// or call <see cref="Enable"/>.
    /// </summary>
    public const string EnableSwitchName = "Moongazing.OrionVault.Testing.EnableDangerousTestKeys";

    // Lazy so Enable() can run first: an eager static would opt the whole process in at type-load
    // time, before any test setup had a chance to say yes.
    private static readonly Lazy<DangerousTestKeyProvider> DefaultInstance =
        new(static () => new DangerousTestKeyProvider(activeKeyId: 1), LazyThreadSafetyMode.ExecutionAndPublication);

    private readonly ConcurrentDictionary<short, byte[]> keys = new();

    /// <summary>Creates a provider whose <paramref name="activeKeyId"/> maps to 32 zero bytes.</summary>
    /// <exception cref="InvalidOperationException">The process has not opted in. See <see cref="Enable"/>.</exception>
    public DangerousTestKeyProvider(short activeKeyId = 1)
    {
        ThrowIfNotEnabled();
        ActiveKeyId = activeKeyId;
        keys[activeKeyId] = new byte[32];
    }

    /// <summary>
    /// Opts this process in to the zero-key test double. Call it once from test setup (a module
    /// initializer or assembly fixture). Never call it from application code.
    /// </summary>
    public static void Enable() => AppContext.SetSwitch(EnableSwitchName, true);

    /// <summary>Shared single-key instance. Throws unless the process has opted in via <see cref="Enable"/>.</summary>
    /// <exception cref="InvalidOperationException">The process has not opted in. See <see cref="Enable"/>.</exception>
    public static DangerousTestKeyProvider Default
    {
        get
        {
            // Checked HERE, outside the cached factory, and not left to the constructor's own
            // check to surface through Lazy<T>. ExecutionAndPublication caches a factory exception
            // for the life of the process, so a first touch before opt-in would poison Default
            // permanently - and the fix this type's own error message prescribes (call Enable(),
            // re-run) would not work without restarting the host, which is exactly where that
            // message gets read. Guarding outside the factory keeps the opt-in retryable in
            // process; nothing is cached until the switch is on.
            ThrowIfNotEnabled();
            return DefaultInstance.Value;
        }
    }

    /// <inheritdoc />
    public short ActiveKeyId { get; }

    /// <summary>Registers an additional 32-byte key under <paramref name="keyId"/>.</summary>
    public void Add(short keyId, ReadOnlyMemory<byte> key)
    {
        if (key.Length != 32)
        {
            throw new ArgumentException("Key must be exactly 32 bytes.", nameof(key));
        }

        keys[keyId] = key.ToArray();
    }

    /// <inheritdoc />
    public ReadOnlyMemory<byte>? TryGetKey(short keyId)
    {
        if (keys.TryGetValue(keyId, out var k))
        {
            return k;
        }

        return null;
    }

    private static void ThrowIfNotEnabled()
    {
        // Fails closed, deliberately: the opt-in branch is taken only when TryGetSwitch reports
        // the switch is defined AND its value is true. An undefined switch, and a configured
        // value that does not parse as a bool, both leave TryGetSwitch returning false, so the
        // provider refuses. There is no path where a malformed value reads as "enabled".
        if (AppContext.TryGetSwitch(EnableSwitchName, out var enabled) && enabled)
        {
            return;
        }

        // The whole support experience for this exception is this string: whoever hits it is
        // mid-test-run and annoyed, so it carries the fix verbatim rather than pointing at docs.
        throw new InvalidOperationException(
            $"""
             {nameof(DangerousTestKeyProvider)} serves an all-zero AES key - a publicly known key that protects
             nothing - and refused to construct because this process never opted in.

             If this is a test project, add the opt-in. Either put this in test setup:

                 {nameof(DangerousTestKeyProvider)}.{nameof(Enable)}();

             (a [ModuleInitializer] runs it before the first test), or add this to the .csproj:

                 <ItemGroup>
                   <RuntimeHostConfigurationOption Include="{EnableSwitchName}" Value="true" />
                 </ItemGroup>

             If this is NOT a test project, do not add either one: OrionVault.Testing has leaked into a
             shipped build. Reference it with PrivateAssets="all" and register a real IKeyProvider.
             """);
    }
}
