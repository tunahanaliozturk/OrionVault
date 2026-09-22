namespace Moongazing.OrionVault.Exceptions;

using Moongazing.OrionVault.Rotation;

/// <summary>
/// Thrown when a rotation cycle fails part-way through its sweep - the row source stops producing
/// mid-enumeration (a dropped connection between pages, a revoked permission, a lock taken by a
/// migration), or a row write fails in a way the per-row guard does not cover.
/// <para>
/// It exists to carry <see cref="Partial"/>: the tallies as they stood at the instant of the
/// throw, read in the same scope that incremented them rather than reconstructed afterwards. A
/// cycle that rotated four thousand rows and then lost its connection has really rotated them -
/// the writes are committed - and reporting that failure as "nothing happened" is a confident
/// false statement, which is worse than silence because it gives the operator no reason to look.
/// Anything the caller reports from this exception must say the counts are PARTIAL: they describe
/// a cycle that did not finish, not a completed one.
/// </para>
/// <para>
/// A failure that never reached a row at all - the source could not be resolved, the key provider
/// threw - is not wrapped in this type, so an unwrapped exception genuinely means zero rows.
/// </para>
/// </summary>
public sealed class OrionVaultRotationCycleException : Exception
{
    /// <summary>
    /// The cycle's tallies at the moment it failed. Every counted row really was scanned, rotated,
    /// skipped, or errored before the failure; the cycle simply stopped before reaching the rest.
    /// </summary>
    public RotationCycleResult Partial { get; } = RotationCycleResult.Empty;

    public OrionVaultRotationCycleException() { }

    public OrionVaultRotationCycleException(string message) : base(message) { }

    public OrionVaultRotationCycleException(string message, Exception innerException)
        : base(message, innerException) { }

    public OrionVaultRotationCycleException(string message, RotationCycleResult partial, Exception innerException)
        : base(message, innerException)
    {
        ArgumentNullException.ThrowIfNull(partial);
        Partial = partial;
    }
}
