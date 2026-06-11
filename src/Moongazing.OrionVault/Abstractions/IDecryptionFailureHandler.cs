namespace Moongazing.OrionVault.Abstractions;

/// <summary>
/// v0.2.19 consumer-supplied observer invoked when an AES-GCM decrypt fails. Useful for
/// routing the failure to an external alerting system (Slack, PagerDuty, SIEM) without
/// baking the routing into the encryptor. Registered via DI; resolved per-call.
/// </summary>
/// <remarks>
/// <para>
/// The handler runs AFTER the failure counter increments and BEFORE the
/// <see cref="OrionVaultDecryptionException"/> propagates out of the encryptor, so a
/// throwing handler does NOT mask the underlying failure (the original exception still
/// bubbles up after the handler call). Handler exceptions are caught and logged via the
/// existing telemetry; they do not surface to the caller.
/// </para>
/// <para>
/// No handler is registered by default. Consumers wire one via
/// <c>services.AddSingleton&lt;IDecryptionFailureHandler, MyHandler&gt;()</c>.
/// </para>
/// </remarks>
public interface IDecryptionFailureHandler
{
    /// <summary>Notify the handler that a decrypt failed.</summary>
    /// <param name="reason">Short reason tag (<c>tampered</c>, <c>key_not_found</c>).</param>
    /// <param name="keyId">Key id that was used or referenced at failure time.</param>
    /// <param name="exception">The exception that was about to be thrown to the caller.</param>
    void OnDecryptionFailed(string reason, short keyId, System.Exception exception);
}

/// <summary>Default no-op handler used when no consumer-registered handler is present.</summary>
public sealed class NullDecryptionFailureHandler : IDecryptionFailureHandler
{
    /// <inheritdoc />
    public void OnDecryptionFailed(string reason, short keyId, System.Exception exception)
    {
        // no-op
    }
}
