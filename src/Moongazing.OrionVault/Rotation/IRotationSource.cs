namespace Moongazing.OrionVault.Rotation;

/// <summary>
/// Stream of (handle, ciphertext) pairs the
/// <see cref="EncryptionRotationHostedService"/> walks to drive a key rotation pass.
/// Implementations bind to whatever storage the encrypted columns live in (EF Core
/// table, Cosmos query, S3 listing) and yield row handles the host can re-write through
/// <see cref="UpdateAsync"/>.
/// </summary>
/// <typeparam name="THandle">
/// Opaque handle the source uses to identify the row again on the update call. Often a
/// primary-key tuple. The host does not interpret it.
/// </typeparam>
public interface IRotationSource<THandle>
{
    /// <summary>
    /// Enumerate eligible rows. The source decides batching and ordering.
    /// </summary>
    IAsyncEnumerable<RotationCandidate<THandle>> EnumerateAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Persist <paramref name="ciphertext"/> back against the row identified by
    /// <paramref name="handle"/>. The host calls this after re-encrypting under the
    /// active key.
    /// </summary>
    Task UpdateAsync(THandle handle, byte[] ciphertext, CancellationToken cancellationToken);
}

/// <summary>A row the rotation host can re-encrypt.</summary>
/// <param name="Handle">Caller-supplied handle the source uses to identify the row on update.</param>
/// <param name="Ciphertext">Current ciphertext value.</param>
#pragma warning disable CA1819 // byte[] is the canonical ciphertext payload shape (matches IEncryptor)
public sealed record RotationCandidate<THandle>(THandle Handle, byte[] Ciphertext);
#pragma warning restore CA1819
