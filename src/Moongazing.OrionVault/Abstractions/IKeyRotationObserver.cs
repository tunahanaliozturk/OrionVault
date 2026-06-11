namespace Moongazing.OrionVault.Abstractions;

using Moongazing.OrionVault.Rotation;

/// <summary>
/// v0.2.20 DI-based observer for key-rotation cycles. Mirrors the existing
/// <c>EncryptionRotationOptions.ProgressCallback</c> options-based hook but registered
/// via DI so it composes with the rest of the host's services (logger factories, tenant
/// scopes, etc.) without forcing consumers to wire a closure inside their options
/// builder.
/// </summary>
/// <remarks>
/// <para>
/// The observer runs AFTER the OpenTelemetry counters / last-cycle gauges are updated
/// and AFTER the structured log line fires, so a throwing observer cannot mask the
/// authoritative metrics. Observer exceptions are caught and logged; they do not abort
/// the rotation sweep.
/// </para>
/// <para>
/// No observer is registered by default. Consumers wire one via
/// <c>services.AddSingleton&lt;IKeyRotationObserver, MyObserver&gt;()</c>. The
/// <see cref="EncryptionRotationOptions.ProgressCallback"/> options-based hook continues
/// to work; both fire when both are configured.
/// </para>
/// </remarks>
public interface IKeyRotationObserver
{
    /// <summary>Notify the observer that one rotation cycle completed.</summary>
    /// <param name="result">Per-cycle totals (scanned / rotated / skipped / errored).</param>
    void OnRotationCycleCompleted(RotationCycleResult result);
}

/// <summary>Default no-op observer used when no consumer-registered observer is present.</summary>
public sealed class NullKeyRotationObserver : IKeyRotationObserver
{
    /// <inheritdoc />
    public void OnRotationCycleCompleted(RotationCycleResult result)
    {
        // no-op
    }
}
