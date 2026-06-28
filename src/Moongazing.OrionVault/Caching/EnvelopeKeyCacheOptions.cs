namespace Moongazing.OrionVault.Caching;

using Moongazing.OrionVault.Exceptions;

/// <summary>
/// Opt-in configuration for the envelope-key cache (v0.4.0). When enabled, an envelope-encryption
/// provider unwraps its data keys through <see cref="CachingKeyProvider"/> instead of holding the
/// startup snapshot for the process lifetime: the unwrapped map is re-fetched once its
/// <see cref="Ttl"/> has elapsed, so a data key disabled / revoked / rotated at the KMS is picked
/// up without a host restart.
/// </summary>
/// <remarks>
/// Caching is OFF by default across every provider; the historical unwrap-once behaviour stays the
/// default. Enabling it trades a bounded amount of staleness (up to <see cref="Ttl"/>) for the
/// ability to react to KMS-side key changes on a long-running host.
/// </remarks>
public sealed class EnvelopeKeyCacheOptions
{
    /// <summary>
    /// Whether the refreshing cache is active. Defaults to <c>false</c> so providers keep the
    /// unwrap-once-at-startup behaviour unless the consumer opts in.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// How long an unwrapped key snapshot is served before the next lookup triggers a refresh
    /// against the KMS. Defaults to 15 minutes. Must be strictly positive when
    /// <see cref="Enabled"/> is <c>true</c>.
    /// </summary>
    public TimeSpan Ttl { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// When a refresh fails (KMS unreachable, throttled, a transient authorization blip) and a
    /// previously unwrapped snapshot is still in hand, keep serving that snapshot rather than
    /// surfacing the failure. Defaults to <c>true</c> so a momentary KMS outage does not take the
    /// application's decrypt path down. The very first unwrap (no snapshot yet) always propagates
    /// its failure regardless of this flag. Set to <c>false</c> to fail closed instead.
    /// </summary>
    public bool ServeStaleOnRefreshFailure { get; set; } = true;

    /// <summary>
    /// Validates the option combination. Called by the provider wiring before a
    /// <see cref="CachingKeyProvider"/> is constructed so a misconfiguration fails fast at startup.
    /// </summary>
    public void Validate()
    {
        if (Enabled && Ttl <= TimeSpan.Zero)
        {
            throw new OrionVaultConfigurationException(
                $"EnvelopeKeyCacheOptions.Ttl must be strictly positive when caching is enabled; got {Ttl}.");
        }
    }
}
