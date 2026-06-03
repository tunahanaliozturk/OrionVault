namespace Moongazing.OrionVault.Abstractions;

/// <summary>
/// Consumer-supplied hook the background re-encryption hosted service calls once per
/// scheduled tick. The implementation queries its own data store for rows still encrypted
/// under retired keys, decrypts each using the multi-key read path, re-encrypts under the
/// current <see cref="IKeyProvider.ActiveKeyId"/>, and persists. Returns the count of rows
/// re-encrypted in the batch so the host service can surface the number on the
/// <c>orionvault.reencryption.rows_processed</c> counter.
/// </summary>
/// <remarks>
/// <para>
/// OrionVault does not assume a single data store, so the row enumeration and persistence
/// stay on the consumer side. The hosted service handles scheduling, observability, and
/// shutdown drain; the target handles "what does a row look like and where do I read/write it".
/// </para>
/// <para>
/// Implementations must be safe to run alongside normal traffic. If the underlying store
/// supports it, the implementation should use row-level locking or an idempotent compare-and-set
/// so a re-encrypted row is not double-written by another instance.
/// </para>
/// </remarks>
public interface IReEncryptionTarget
{
    /// <summary>
    /// Re-encrypt one batch of rows. Implementations choose the batch size internally;
    /// the hosted service caps invocation frequency via
    /// <see cref="Options.ReEncryptionOptions.Schedule"/>.
    /// </summary>
    /// <param name="cancellationToken">Cooperative cancellation from the host's stopping token.</param>
    /// <returns>The number of rows successfully re-encrypted in this batch.</returns>
    Task<int> ReEncryptBatchAsync(CancellationToken cancellationToken);
}
