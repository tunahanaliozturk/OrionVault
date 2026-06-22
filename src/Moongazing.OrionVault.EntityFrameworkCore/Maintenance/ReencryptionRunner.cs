namespace Moongazing.OrionVault.EntityFrameworkCore.Maintenance;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.BlindIndex;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.Rotation;

/// <summary>
/// EF Core implementation of <see cref="IEncryptionMaintenance"/>. Walks a mapped entity type in
/// bounded, ordered batches and brings every row up to the active encryption key and active
/// blind-index version, reusing <see cref="EncryptionRotator"/> and
/// <see cref="IBlindIndexProvider"/> rather than re-implementing any cryptography. Thread-safe;
/// register as a singleton (the per-run <see cref="DbContext"/> is supplied by the caller).
/// </summary>
public sealed partial class ReencryptionRunner : IEncryptionMaintenance
{
    private readonly IEncryptor _encryptor;
    private readonly IKeyProvider _keys;
    private readonly IBlindIndexProvider? _blindIndex;
    private readonly OrionVaultDiagnostics? _diagnostics;
    private readonly ILogger<ReencryptionRunner> _logger;

    /// <summary>
    /// Creates a runner. <paramref name="blindIndex"/> and <paramref name="diagnostics"/> are
    /// optional: a plan that registers a blind-index column requires the provider (the runner
    /// throws a clear error if it is missing), and telemetry is emitted only when diagnostics are
    /// wired.
    /// </summary>
    public ReencryptionRunner(
        IEncryptor encryptor,
        IKeyProvider keys,
        IBlindIndexProvider? blindIndex = null,
        OrionVaultDiagnostics? diagnostics = null,
        ILogger<ReencryptionRunner>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(encryptor);
        ArgumentNullException.ThrowIfNull(keys);
        _encryptor = encryptor;
        _keys = keys;
        _blindIndex = blindIndex;
        _diagnostics = diagnostics;
        _logger = logger ?? NullLogger<ReencryptionRunner>.Instance;
    }

    /// <inheritdoc />
    public async Task<ReencryptionReport> RunAsync<TEntity>(
        DbContext context,
        ReencryptionPlan<TEntity> plan,
        CancellationToken cancellationToken = default)
        where TEntity : class
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(plan);
        plan.Validate();

        var requiresBlindIndex = false;
        foreach (var column in plan.Columns)
        {
            if (column.HasBlindIndex)
            {
                requiresBlindIndex = true;
                break;
            }
        }

        if (requiresBlindIndex && _blindIndex is null)
        {
            throw new InvalidOperationException(
                $"ReencryptionPlan<{typeof(TEntity).Name}> registers a blind-index column but no " +
                "IBlindIndexProvider is registered. Call options.UseBlindIndex(...) when adding OrionVault, " +
                "or remove the blind-index pairing from the plan.");
        }

        var activeKeyId = _keys.ActiveKeyId;
        var activeIndexVersion = _blindIndex?.ActiveVersion ?? 0;
        var sw = System.Diagnostics.Stopwatch.StartNew();

        var total = ReencryptionReport.Empty;
        var offset = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Tracking query so mutated rows are flagged Modified and SaveChanges writes them.
            // Ordered Skip/Take paging: the sort key (typically the PK) is never an encrypted
            // column, so it does not change when a row is re-encrypted - the window stays stable
            // across the writes this pass makes.
            var batch = await plan.OrderBy(context.Set<TEntity>())
                .Skip(offset)
                .Take(plan.BatchSize)
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false);

            if (batch.Count == 0)
            {
                break;
            }

            var batchReport = ProcessBatch(plan, batch, activeKeyId, activeIndexVersion);
            // Persist this batch before moving on so an interruption leaves a prefix of the table
            // already migrated (resumable). SaveChanges only writes the rows actually mutated.
            await context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

            total = total.Add(batchReport);
            EmitBatchTelemetry(batchReport);

            // Advance by the number of rows FETCHED, not modified: skipped rows must still be
            // stepped over or the next page would re-fetch them. Because the order is by an
            // immutable key, this never double-processes or misses a row.
            offset += batch.Count;

            // Detach this batch's entities now that they are saved. BatchSize bounds the QUERY, not
            // the change tracker: without this clear a long run accumulates every processed entity,
            // growing memory unbounded and forcing each later SaveChanges/DetectChanges to re-scan
            // all previously processed rows (O(n^2) over the table). The paging cursor is the local
            // 'offset' above, which is independent of tracker state, so clearing here does not skip
            // or re-fetch rows - the next Skip(offset)/Take resumes exactly where this batch ended.
            context.ChangeTracker.Clear();

            if (batch.Count < plan.BatchSize)
            {
                break;
            }
        }

        sw.Stop();
        _diagnostics?.RotationCycleDuration.Record(sw.Elapsed.TotalMilliseconds);
        _diagnostics?.SetLastCycleSnapshot(total.Scanned, total.ReEncrypted, total.Skipped, total.Errors);
        LogPass(typeof(TEntity).Name, total.Scanned, total.ReEncrypted, total.ReIndexed, total.Skipped, total.Errors, sw.Elapsed);
        return total;
    }

    private ReencryptionReport ProcessBatch<TEntity>(
        ReencryptionPlan<TEntity> plan,
        List<TEntity> batch,
        short activeKeyId,
        short activeIndexVersion)
        where TEntity : class
    {
        var scanned = 0;
        var reEncrypted = 0;
        var reIndexed = 0;
        var skipped = 0;
        var errors = 0;

        foreach (var entity in batch)
        {
            scanned++;
            try
            {
                var (rowReEncrypted, rowReIndexed) = ProcessRow(plan, entity, activeKeyId, activeIndexVersion);
                if (rowReEncrypted)
                {
                    reEncrypted++;
                }

                if (rowReIndexed)
                {
                    reIndexed++;
                }

                if (!rowReEncrypted && !rowReIndexed)
                {
                    skipped++;
                }
            }
#pragma warning disable CA1031 // one malformed row must not abort the sweep; it is counted and logged
            catch (Exception ex)
#pragma warning restore CA1031
            {
                errors++;
                LogRowFailed(ex);
            }
        }

        return new ReencryptionReport(scanned, reEncrypted, reIndexed, skipped, errors);
    }

    private (bool ReEncrypted, bool ReIndexed) ProcessRow<TEntity>(
        ReencryptionPlan<TEntity> plan,
        TEntity entity,
        short activeKeyId,
        short activeIndexVersion)
        where TEntity : class
    {
        var rowReEncrypted = false;
        var rowReIndexed = false;

        foreach (var column in plan.Columns)
        {
            var cipher = column.ReadCipher(entity);

            // A null encrypted column stays null (matches the EF value-converter null semantics);
            // there is nothing to rotate and nothing to index.
            if (cipher is null)
            {
                continue;
            }

            // Decrypt lazily and at most once per column: needed when the ciphertext must be
            // rotated (to re-encrypt under the active key) OR when the paired blind index is stale
            // (to recompute the token from the plaintext). The plaintext is identical before and
            // after rotation, so a single decrypt serves both.
            string? plaintext = null;
            var decrypted = false;

            if (EncryptionRotator.NeedsRotation(cipher, activeKeyId))
            {
                if (column.IsString)
                {
                    plaintext = _encryptor.DecryptString(cipher);
                    decrypted = true;
                    column.WriteCipher(entity, _encryptor.EncryptString(plaintext));
                }
                else
                {
                    column.WriteCipher(entity, EncryptionRotator.Rotate(_encryptor, cipher));
                }

                rowReEncrypted = true;
            }

            if (column.HasBlindIndex && IsIndexStale(column.ReadIndex!(entity), activeIndexVersion))
            {
                if (!decrypted)
                {
                    // Either the ciphertext did not need rotation or it is a byte column without a
                    // captured plaintext; decrypt now to recompute the index from the plaintext.
                    plaintext = _encryptor.DecryptString(cipher);
                }

                // _blindIndex is non-null here: a column with HasBlindIndex is only allowed when a
                // provider is registered (enforced in RunAsync), and only string columns can carry
                // a blind index (enforced by the EncryptedColumnPlan factory).
                var token = _blindIndex!.Compute(plaintext!);
                column.WriteIndex!(entity, token.Bytes);
                rowReIndexed = true;
            }
        }

        return (rowReEncrypted, rowReIndexed);
    }

    private static bool IsIndexStale(byte[]? storedIndex, short activeIndexVersion)
    {
        // A missing or malformed token is treated as stale so the pass repairs it by writing a
        // fresh active-version token. A readable token is stale only when its version differs from
        // the active version.
        //
        // The length gate is load-bearing and must mirror the search path
        // (HmacBlindIndexProvider.Matches), which rejects any token whose length != TotalSize
        // BEFORE comparing. TryReadVersion only requires VersionSize (2) bytes, so a truncated or
        // over-long token whose first two bytes happen to equal the active version would otherwise
        // read as "current" and be skipped - leaving a row that search can never match. Requiring
        // the exact TotalSize here forces such a token to be recomputed into a well-formed,
        // searchable one.
        if (storedIndex is null
            || storedIndex.Length != BlindIndexResult.TotalSize
            || !BlindIndexResult.TryReadVersion(storedIndex, out var version))
        {
            return true;
        }

        return version != activeIndexVersion;
    }

    private void EmitBatchTelemetry(ReencryptionReport report)
    {
        if (_diagnostics is null)
        {
            return;
        }

        if (report.ReEncrypted > 0)
        {
            _diagnostics.RotationRowsRotated.Add(report.ReEncrypted);
        }

        if (report.Skipped > 0)
        {
            _diagnostics.RotationRowsSkipped.Add(report.Skipped);
        }

        if (report.Errors > 0)
        {
            _diagnostics.RotationRowErrors.Add(report.Errors);
        }
    }

    [LoggerMessage(EventId = 1, Level = LogLevel.Information,
        Message = "OrionVault re-encryption pass over {Entity} complete: scanned={Scanned} reEncrypted={ReEncrypted} reIndexed={ReIndexed} skipped={Skipped} errors={Errors} duration={Duration}")]
    private partial void LogPass(string entity, int scanned, int reEncrypted, int reIndexed, int skipped, int errors, TimeSpan duration);

    [LoggerMessage(EventId = 2, Level = LogLevel.Error,
        Message = "OrionVault re-encryption skipped a row that threw during decrypt / re-encrypt / re-index (row counted as an error; pass continues)")]
    private partial void LogRowFailed(Exception ex);
}
