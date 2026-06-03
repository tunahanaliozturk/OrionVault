namespace Moongazing.OrionVault.Options;

/// <summary>
/// Tuning knobs for the background re-encryption hosted service. Off by default; opt in via
/// <c>builder.UseReEncryptionService(...)</c>.
/// </summary>
public sealed class ReEncryptionOptions
{
    /// <summary>
    /// Interval between successive batches. Default 6 hours. Set to a value smaller than the
    /// expected re-encryption duration with care - the hosted service does not overlap ticks.
    /// </summary>
    public TimeSpan Schedule { get; set; } = TimeSpan.FromHours(6);

    /// <summary>
    /// When <see langword="false"/> the hosted service short-circuits each tick without
    /// invoking the target. Useful for feature-flagging the drain in production without
    /// re-registering services. Default <see langword="true"/>.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Maximum time the service will wait for an in-flight batch to complete during host
    /// shutdown before tearing down. The cancellation token is signalled either way; this
    /// caps how long the <c>StopAsync</c> path blocks. Default 30 seconds.
    /// </summary>
    public TimeSpan DrainTimeout { get; set; } = TimeSpan.FromSeconds(30);
}
