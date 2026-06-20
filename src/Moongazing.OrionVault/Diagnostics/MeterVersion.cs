namespace Moongazing.OrionVault.Diagnostics;

using System.Reflection;

/// <summary>
/// Resolves the diagnostics version (used for the <see cref="System.Diagnostics.Metrics.Meter"/>
/// and <see cref="System.Diagnostics.ActivitySource"/>) once from this assembly's informational
/// version, so the telemetry version always tracks the shipped package version instead of a
/// hardcoded literal that drifts out of sync on every release.
/// </summary>
internal static class MeterVersion
{
    /// <summary>
    /// The resolved version string (build metadata stripped), e.g. <c>0.3.1</c>.
    /// </summary>
    public static string Value { get; } = Resolve();

    private static string Resolve()
    {
        var asm = typeof(MeterVersion).Assembly;
        var info = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrEmpty(info))
        {
            var plus = info.IndexOf('+', StringComparison.Ordinal);
            return plus >= 0 ? info[..plus] : info;
        }
        return asm.GetName().Version?.ToString(3) ?? "0.0.0";
    }
}
