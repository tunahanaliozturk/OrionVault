namespace Moongazing.OrionVault.EntityFrameworkCore.Maintenance;

using Microsoft.EntityFrameworkCore;
using Moongazing.OrionVault.Rotation;

/// <summary>
/// Operator-facing entry point for the v0.3.4 re-encryption / blind-index re-index pass. After
/// rolling the active encryption key (and / or the active blind-index version), existing rows
/// still carry the previous key id in their AES-GCM header and the previous version in their
/// blind-index token. <see cref="RunAsync"/> walks an EF Core table in bounded batches and brings
/// every row up to the active key and active index version.
/// <para>
/// The pass is built on the shipped primitives - <see cref="EncryptionRotator"/> for the
/// ciphertext and <see cref="Abstractions.IBlindIndexProvider"/> /
/// <see cref="BlindIndexResult.TryReadVersion"/> for the index - so it inherits their exact
/// envelope and token semantics and never re-implements cryptography.
/// </para>
/// <para>
/// It is idempotent (a row already on the active key id AND active index version is left
/// untouched and counted as skipped) and resumable (safe to re-run after an interruption: the
/// second run re-scans from the start but no-ops every already-migrated row). Per-row failures
/// are swallowed and counted so a single malformed blob does not abort the sweep. Resolve this
/// service from DI after calling <c>UseReencryptionRunner()</c> on the OrionVault builder.
/// </para>
/// <para>
/// The plan's column accessors read and write the RAW stored envelope bytes, not the decrypted
/// CLR value. Run the pass against a <see cref="DbContext"/> that maps the encrypted columns as
/// plain <c>byte[]</c> (without the OrionVault value converter attached) so the runner sees the
/// real on-disk envelope: this is what lets <see cref="EncryptionRotator.NeedsRotation"/> skip
/// rows already on the active key cheaply by header, and what gives the runner explicit control
/// over exactly when it decrypts and re-encrypts. Routing the pass through the normal encrypting
/// context would auto-decrypt on read under the old key and auto-encrypt on write, which both
/// defeats the cheap skip and rewrites every row unconditionally.
/// </para>
/// </summary>
public interface IEncryptionMaintenance
{
    /// <summary>
    /// Runs a full re-encryption / re-index pass over <typeparamref name="TEntity"/> using the
    /// supplied <paramref name="plan"/>, against the supplied <paramref name="context"/>. Pages
    /// the table in <see cref="ReencryptionPlan{TEntity}.BatchSize"/>-sized batches, saving after
    /// each batch, and returns the aggregate tallies.
    /// </summary>
    /// <typeparam name="TEntity">The entity type to sweep.</typeparam>
    /// <param name="context">
    /// The <see cref="DbContext"/> whose table is swept. The caller owns its lifetime; the runner
    /// uses tracking queries and calls <see cref="DbContext.SaveChangesAsync(CancellationToken)"/>
    /// on it once per batch.
    /// </param>
    /// <param name="plan">The plan describing the ordering, encrypted columns, and batch size.</param>
    /// <param name="cancellationToken">
    /// Cooperative cancellation. Honoured between batches and on each EF Core await; a cancelled
    /// run leaves already-saved batches persisted (the pass is resumable, so re-running finishes
    /// the remainder).
    /// </param>
    /// <returns>A <see cref="ReencryptionReport"/> with scanned / re-encrypted / re-indexed / skipped / error counts.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> or <paramref name="plan"/> is null.</exception>
    /// <exception cref="InvalidOperationException">
    /// The plan registers a blind-index column but no <see cref="Abstractions.IBlindIndexProvider"/>
    /// is registered, or the plan has no columns.
    /// </exception>
    Task<ReencryptionReport> RunAsync<TEntity>(
        DbContext context,
        ReencryptionPlan<TEntity> plan,
        CancellationToken cancellationToken = default)
        where TEntity : class;
}
