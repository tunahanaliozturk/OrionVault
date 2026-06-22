namespace Moongazing.OrionVault.EntityFrameworkCore.Maintenance;

using Microsoft.EntityFrameworkCore;

/// <summary>
/// Declarative description of a re-encryption / blind-index re-index pass over a single
/// EF Core entity type <typeparamref name="TEntity"/>: which rows to walk (and in what stable
/// order, so the batched pass is deterministic and resumable), which encrypted columns to
/// refresh, and how large each batch is.
/// <para>
/// The plan carries strongly-typed delegates only - no reflection over the EF model - so the
/// runner that consumes it stays allocation-light, trim-friendly, and trivially unit-testable.
/// Build one with <see cref="ReencryptionPlan.For{TEntity}"/>.
/// </para>
/// </summary>
/// <typeparam name="TEntity">The entity type to sweep. Must be a mapped EF Core entity.</typeparam>
public sealed class ReencryptionPlan<TEntity>
    where TEntity : class
{
    private readonly List<EncryptedColumnPlan<TEntity>> _columns = [];

    internal ReencryptionPlan(Func<IQueryable<TEntity>, IOrderedQueryable<TEntity>> orderBy)
    {
        OrderBy = orderBy;
    }

    /// <summary>
    /// Applies the stable ordering the batched pass pages over. A stable, total order (typically
    /// the primary key) is required so successive <c>Skip</c>/<c>Take</c> batches do not overlap
    /// or skip rows. Re-encrypting a row does not change its key, so the order is invariant across
    /// the pass and a resumed run re-scans deterministically.
    /// </summary>
    internal Func<IQueryable<TEntity>, IOrderedQueryable<TEntity>> OrderBy { get; }

    /// <summary>The encrypted columns this pass refreshes. At least one is required.</summary>
    internal IReadOnlyList<EncryptedColumnPlan<TEntity>> Columns => _columns;

    /// <summary>
    /// Rows fetched, processed, and saved per batch. Bounds working-set memory and transaction
    /// size on a large table. Default 500.
    /// </summary>
    public int BatchSize { get; private set; } = 500;

    /// <summary>
    /// Registers an encrypted column to refresh. Call once per encrypted column on the entity.
    /// Returns the same plan for chaining.
    /// </summary>
    /// <param name="column">A column plan from <see cref="EncryptedColumnPlan{TEntity}"/> factory methods.</param>
    public ReencryptionPlan<TEntity> WithColumn(EncryptedColumnPlan<TEntity> column)
    {
        ArgumentNullException.ThrowIfNull(column);
        _columns.Add(column);
        return this;
    }

    /// <summary>
    /// Sets the per-batch row count. Must be at least 1. Default 500.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="batchSize"/> is below 1.</exception>
    public ReencryptionPlan<TEntity> WithBatchSize(int batchSize)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(batchSize, 1);
        BatchSize = batchSize;
        return this;
    }

    internal void Validate()
    {
        if (_columns.Count == 0)
        {
            throw new InvalidOperationException(
                $"ReencryptionPlan<{typeof(TEntity).Name}> has no columns. Call WithColumn at least once.");
        }
    }
}

/// <summary>
/// Entry point for building a <see cref="ReencryptionPlan{TEntity}"/>.
/// </summary>
public static class ReencryptionPlan
{
    /// <summary>
    /// Begins a plan for <typeparamref name="TEntity"/> with the stable ordering the batched pass
    /// pages over. Add columns with <see cref="ReencryptionPlan{TEntity}.WithColumn"/>.
    /// </summary>
    /// <param name="orderBy">
    /// Applies a stable, total ordering (typically the primary key, for example
    /// <c>q =&gt; q.OrderBy(e =&gt; e.Id)</c>). Required so successive batches do not overlap or skip
    /// rows; an unstable order can silently miss rows on a large table.
    /// </param>
    public static ReencryptionPlan<TEntity> For<TEntity>(
        Func<IQueryable<TEntity>, IOrderedQueryable<TEntity>> orderBy)
        where TEntity : class
    {
        ArgumentNullException.ThrowIfNull(orderBy);
        return new ReencryptionPlan<TEntity>(orderBy);
    }
}
