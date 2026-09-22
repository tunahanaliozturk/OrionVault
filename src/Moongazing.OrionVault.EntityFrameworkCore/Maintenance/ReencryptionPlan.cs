namespace Moongazing.OrionVault.EntityFrameworkCore.Maintenance;

using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;

/// <summary>
/// Declarative description of a re-encryption / blind-index re-index pass over a single
/// EF Core entity type <typeparamref name="TEntity"/>: which rows to walk (and by which stable
/// key, so the batched pass is deterministic and resumable), which encrypted columns to
/// refresh, and how large each batch is.
/// <para>
/// The plan carries strongly-typed delegates only - no reflection over the EF model - so the
/// runner that consumes it stays allocation-light, trim-friendly, and trivially unit-testable.
/// Build one with <see cref="ReencryptionPlan.For{TEntity, TKey}"/>.
/// </para>
/// </summary>
/// <typeparam name="TEntity">The entity type to sweep. Must be a mapped EF Core entity.</typeparam>
public sealed class ReencryptionPlan<TEntity>
    where TEntity : class
{
    private readonly List<EncryptedColumnPlan<TEntity>> _columns = [];

    internal ReencryptionPlan(
        Func<IQueryable<TEntity>, IOrderedQueryable<TEntity>> orderBy,
        Func<IQueryable<TEntity>, object, IQueryable<TEntity>> after,
        Func<TEntity, object> readKey)
    {
        OrderBy = orderBy;
        After = after;
        ReadKey = readKey;
    }

    /// <summary>
    /// Orders a query by the plan's key. A stable, total order (typically the primary key) is
    /// required so successive batches are deterministic. Re-encrypting a row never changes its
    /// key, so the order is invariant across the pass and a resumed run re-scans deterministically.
    /// </summary>
    internal Func<IQueryable<TEntity>, IOrderedQueryable<TEntity>> OrderBy { get; }

    /// <summary>
    /// Narrows a query to the rows whose key sorts strictly AFTER the supplied cursor - the keyset
    /// half of the paging. Unlike an offset, a key cursor says WHERE to resume rather than HOW MANY
    /// rows to discard, so a row deleted concurrently below the cursor cannot shift the window and
    /// make the pass step over a row it never visited.
    /// </summary>
    internal Func<IQueryable<TEntity>, object, IQueryable<TEntity>> After { get; }

    /// <summary>Reads the key off a fetched row, to become the next batch's cursor.</summary>
    internal Func<TEntity, object> ReadKey { get; }

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
    /// Begins a plan for <typeparamref name="TEntity"/> keyed on <paramref name="keySelector"/>.
    /// Add columns with <see cref="ReencryptionPlan{TEntity}.WithColumn"/>.
    /// </summary>
    /// <param name="keySelector">
    /// Selects the stable, unique, UNENCRYPTED key the pass pages over - typically the primary key,
    /// for example <c>e =&gt; e.Id</c>. The runner both orders by it and resumes each batch from the
    /// previous batch's last value, so it must be unique and must not move while the pass runs
    /// (the pass only ever rewrites encrypted columns, so it never moves the key itself).
    /// </param>
    /// <typeparam name="TEntity">The entity type to sweep.</typeparam>
    /// <typeparam name="TKey">The key's type - any comparable type EF Core can order and compare in SQL.</typeparam>
    public static ReencryptionPlan<TEntity> For<TEntity, TKey>(
        Expression<Func<TEntity, TKey>> keySelector)
        where TEntity : class
        where TKey : notnull, IComparable<TKey>
    {
        ArgumentNullException.ThrowIfNull(keySelector);
        var readKey = keySelector.Compile();
        return new ReencryptionPlan<TEntity>(
            q => q.OrderBy(keySelector),
            (q, cursor) => q.Where(After(keySelector, (TKey)cursor)),
            e => readKey(e));
    }

    /// <summary>
    /// Builds <c>e =&gt; keySelector(e).CompareTo(cursor) &gt; 0</c> by inlining a compiler-emitted
    /// template into the caller's key selector. Going through <see cref="IComparable{T}.CompareTo"/>
    /// rather than the <c>&gt;</c> operator is what lets the key be a <see cref="Guid"/> - the most
    /// common primary key in an EF model, and a type with no comparison operators at all - and
    /// building the node from a template rather than reflecting for a <c>MethodInfo</c> keeps the
    /// plan free of runtime member lookup. EF Core inlines the invocation before translation, so
    /// this reaches the database as a plain <c>WHERE key &gt; @cursor</c>.
    /// </summary>
    private static Expression<Func<TEntity, bool>> After<TEntity, TKey>(
        Expression<Func<TEntity, TKey>> keySelector, TKey cursor)
        where TKey : notnull, IComparable<TKey>
    {
        Expression<Func<TKey, TKey, bool>> after = (key, bound) => key.CompareTo(bound) > 0;
        return Expression.Lambda<Func<TEntity, bool>>(
            Expression.Invoke(after, keySelector.Body, Expression.Constant(cursor, typeof(TKey))),
            keySelector.Parameters);
    }
}
