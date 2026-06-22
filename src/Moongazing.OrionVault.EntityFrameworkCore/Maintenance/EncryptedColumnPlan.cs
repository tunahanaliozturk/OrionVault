namespace Moongazing.OrionVault.EntityFrameworkCore.Maintenance;

using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.BlindIndex;
using Moongazing.OrionVault.Rotation;

/// <summary>
/// Describes one encrypted column on <typeparamref name="TEntity"/> for a re-encryption pass:
/// how to read its current ciphertext, how to write the refreshed ciphertext back, and -
/// optionally - the paired blind-index column to recompute under the active index version.
/// <para>
/// The stored value is the raw AES-GCM envelope (<c>[keyId:2 | nonce:12 | tag:16 | ciphertext:N]</c>),
/// i.e. the bytes the EF Core value converter persists. The runner reads that envelope, asks
/// <see cref="EncryptionRotator.NeedsRotation"/> whether it is still on a non-active key, and only
/// when so decrypts under the embedded key id and re-encrypts under the active key. A blind-index
/// column is refreshed independently: the runner reads its stored token, resolves the version via
/// <see cref="BlindIndexResult.TryReadVersion"/>, and recomputes from the decrypted plaintext under
/// <see cref="IBlindIndexProvider.ActiveVersion"/> only when the stored version is stale.
/// </para>
/// <para>Build one with the factory methods on the non-generic <see cref="EncryptedColumnPlan"/>.</para>
/// </summary>
/// <typeparam name="TEntity">The entity type the column lives on.</typeparam>
public sealed class EncryptedColumnPlan<TEntity>
    where TEntity : class
{
    internal EncryptedColumnPlan(
        string name,
        bool isString,
        Func<TEntity, byte[]?> readCipher,
        Action<TEntity, byte[]?> writeCipher,
        Func<TEntity, byte[]?>? readIndex,
        Action<TEntity, byte[]?>? writeIndex)
    {
        Name = name;
        IsString = isString;
        ReadCipher = readCipher;
        WriteCipher = writeCipher;
        ReadIndex = readIndex;
        WriteIndex = writeIndex;
    }

    /// <summary>A human-readable column name used in diagnostics.</summary>
    public string Name { get; }

    /// <summary>
    /// True when the column is a UTF-8 <see cref="string"/> column (rotated via
    /// <see cref="EncryptionRotator.RotateString"/>); false for a raw <c>byte[]</c> column
    /// (rotated via <see cref="EncryptionRotator.Rotate"/>). A blind index can only be paired
    /// with a string column because the index is computed from the plaintext string.
    /// </summary>
    public bool IsString { get; }

    /// <summary>True when this column has a paired blind-index column to keep re-indexed.</summary>
    public bool HasBlindIndex => ReadIndex is not null && WriteIndex is not null;

    internal Func<TEntity, byte[]?> ReadCipher { get; }
    internal Action<TEntity, byte[]?> WriteCipher { get; }
    internal Func<TEntity, byte[]?>? ReadIndex { get; }
    internal Action<TEntity, byte[]?>? WriteIndex { get; }
}

/// <summary>
/// Factory entry point for <see cref="EncryptedColumnPlan{TEntity}"/>. Kept as a separate
/// non-generic type (rather than static methods on the generic class) so the public surface
/// reads as <c>EncryptedColumnPlan.ForString&lt;Customer&gt;(...)</c> and stays free of
/// static-members-on-generic-types friction.
/// </summary>
public static class EncryptedColumnPlan
{
    /// <summary>
    /// Plan for a raw <c>byte[]</c> encrypted column (no searchable blind index). The accessors
    /// read and write the stored AES-GCM envelope bytes directly.
    /// </summary>
    /// <param name="name">A column name for diagnostics (for example <c>nameof(Customer.IdScan)</c>).</param>
    /// <param name="read">Reads the stored ciphertext bytes from the entity (null when the column is null).</param>
    /// <param name="write">Writes refreshed ciphertext bytes back to the entity.</param>
    public static EncryptedColumnPlan<TEntity> ForBytes<TEntity>(
        string name,
        Func<TEntity, byte[]?> read,
        Action<TEntity, byte[]?> write)
        where TEntity : class
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(read);
        ArgumentNullException.ThrowIfNull(write);
        return new EncryptedColumnPlan<TEntity>(name, isString: false, read, write, readIndex: null, writeIndex: null);
    }

    /// <summary>
    /// Plan for an encrypted UTF-8 <see cref="string"/> column with no searchable blind index.
    /// The accessors read and write the stored AES-GCM envelope bytes (the value the EF Core
    /// string value converter persists), NOT the plaintext string.
    /// </summary>
    /// <param name="name">A column name for diagnostics (for example <c>nameof(Customer.Email)</c>).</param>
    /// <param name="readCipher">Reads the stored ciphertext bytes from the entity (null when the column is null).</param>
    /// <param name="writeCipher">Writes refreshed ciphertext bytes back to the entity.</param>
    public static EncryptedColumnPlan<TEntity> ForString<TEntity>(
        string name,
        Func<TEntity, byte[]?> readCipher,
        Action<TEntity, byte[]?> writeCipher)
        where TEntity : class
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(readCipher);
        ArgumentNullException.ThrowIfNull(writeCipher);
        return new EncryptedColumnPlan<TEntity>(name, isString: true, readCipher, writeCipher, readIndex: null, writeIndex: null);
    }

    /// <summary>
    /// Plan for an encrypted UTF-8 <see cref="string"/> column that is ALSO paired with a
    /// searchable blind-index column. The runner re-encrypts the ciphertext under the active key
    /// (when stale) and, independently, recomputes the blind-index token from the decrypted
    /// plaintext under the active index version (when the stored token's version is stale).
    /// </summary>
    /// <param name="name">A column name for diagnostics (for example <c>nameof(Customer.Email)</c>).</param>
    /// <param name="readCipher">Reads the stored ciphertext bytes for the encrypted column.</param>
    /// <param name="writeCipher">Writes refreshed ciphertext bytes back to the encrypted column.</param>
    /// <param name="readIndex">Reads the stored blind-index token bytes (<see cref="BlindIndexResult.Bytes"/>).</param>
    /// <param name="writeIndex">Writes the recomputed blind-index token bytes back.</param>
    public static EncryptedColumnPlan<TEntity> ForStringWithBlindIndex<TEntity>(
        string name,
        Func<TEntity, byte[]?> readCipher,
        Action<TEntity, byte[]?> writeCipher,
        Func<TEntity, byte[]?> readIndex,
        Action<TEntity, byte[]?> writeIndex)
        where TEntity : class
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(readCipher);
        ArgumentNullException.ThrowIfNull(writeCipher);
        ArgumentNullException.ThrowIfNull(readIndex);
        ArgumentNullException.ThrowIfNull(writeIndex);
        return new EncryptedColumnPlan<TEntity>(name, isString: true, readCipher, writeCipher, readIndex, writeIndex);
    }
}
