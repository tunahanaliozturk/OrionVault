namespace Moongazing.OrionVault.Rotation;

/// <summary>
/// Tallies produced by a re-encryption / blind-index re-index pass (for example
/// <c>Moongazing.OrionVault.EntityFrameworkCore.ReencryptionRunner</c>). Mirrors
/// <see cref="RotationCycleResult"/> on the ciphertext side but additionally tracks the
/// blind-index re-index work that a v0.3.4 pass performs on top of the AES-GCM rotation.
/// </summary>
/// <param name="Scanned">
/// Rows examined. Equals <see cref="ReEncrypted"/> + <see cref="Skipped"/> + <see cref="Errors"/>
/// once a pass has run to completion (a row counted as an error is not also counted as
/// re-encrypted or skipped).
/// </param>
/// <param name="ReEncrypted">
/// Rows whose ciphertext header carried a non-active key id and were re-encrypted under the
/// active key. A row that only needed a blind-index refresh (its ciphertext was already on the
/// active key) is NOT counted here; see <see cref="ReIndexed"/>.
/// </param>
/// <param name="ReIndexed">
/// Rows whose stored blind index carried a non-active version and were recomputed under the
/// active version. Independent of <see cref="ReEncrypted"/>: a row can be re-encrypted,
/// re-indexed, both, or neither. A row that needed both still increments each of the two
/// counters once.
/// </param>
/// <param name="Skipped">
/// Rows already fully on the active key id AND active blind-index version, left untouched. This
/// is the idempotency signal: a second pass over an already-migrated table reports every row as
/// skipped and writes nothing.
/// </param>
/// <param name="Errors">
/// Rows that threw while being decrypted, re-encrypted, or re-indexed. The pass swallows the
/// per-row failure, counts it here, and continues so one malformed blob does not abort the
/// sweep.
/// </param>
public sealed record ReencryptionReport(int Scanned, int ReEncrypted, int ReIndexed, int Skipped, int Errors)
{
    /// <summary>An empty report (all counters zero), useful as a seed when aggregating batches.</summary>
    public static ReencryptionReport Empty { get; } = new(0, 0, 0, 0, 0);

    /// <summary>
    /// Returns a new report with each counter summed with <paramref name="other"/>. Lets a caller
    /// fold per-batch reports into a single run total without mutable accumulator state.
    /// </summary>
    public ReencryptionReport Add(ReencryptionReport other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return new ReencryptionReport(
            Scanned + other.Scanned,
            ReEncrypted + other.ReEncrypted,
            ReIndexed + other.ReIndexed,
            Skipped + other.Skipped,
            Errors + other.Errors);
    }
}
