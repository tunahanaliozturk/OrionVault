namespace Moongazing.OrionVault.Internal;

using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.Exceptions;

internal sealed class AesGcmEncryptor : IEncryptor
{
    private const int KeyLengthBytes = 32;
    private readonly IKeyProvider _keys;
    private readonly OrionVaultDiagnostics _diag;
    // v0.2.19 optional consumer-supplied failure observer. Null when no handler is
    // registered; the encryptor treats null as no-op.
    private readonly Abstractions.IDecryptionFailureHandler? _failureHandler;
    // v0.2.23 optional consumer-registered audit observer. Null and
    // NullEncryptionAuditObserver are both treated as 'no observer'.
    private readonly Abstractions.IEncryptionAuditObserver? _auditObserver;

    public AesGcmEncryptor(IKeyProvider keys, OrionVaultDiagnostics diag)
        : this(keys, diag, failureHandler: null, auditObserver: null)
    {
    }

    /// <summary>v0.2.19 ctor overload that wires the optional <see cref="Abstractions.IDecryptionFailureHandler"/>.</summary>
    public AesGcmEncryptor(IKeyProvider keys, OrionVaultDiagnostics diag, Abstractions.IDecryptionFailureHandler? failureHandler)
        : this(keys, diag, failureHandler, auditObserver: null)
    {
    }

    /// <summary>v0.2.23 ctor overload that also wires the optional <see cref="Abstractions.IEncryptionAuditObserver"/>.</summary>
    public AesGcmEncryptor(
        IKeyProvider keys,
        OrionVaultDiagnostics diag,
        Abstractions.IDecryptionFailureHandler? failureHandler,
        Abstractions.IEncryptionAuditObserver? auditObserver)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(diag);
        _keys = keys;
        _diag = diag;
        _failureHandler = failureHandler is Abstractions.NullDecryptionFailureHandler ? null : failureHandler;
        _auditObserver = auditObserver is Abstractions.NullEncryptionAuditObserver ? null : auditObserver;
        // v0.2.25 fix (codex P2): snapshot the registered key count HERE in the common
        // ctor rather than in the AddOrionVault DI factory, so the keyed-provider path
        // (OrionVaultEncryptor.Create used by UseEntityFrameworkCore(providerName)) and
        // the public factory also populate orionvault.keys.registered_count. Every
        // IEncryptor construction now updates the gauge, matching the documented
        // 'snapshot at IEncryptor construction' contract.
        diag.SetRegisteredKeyCountSnapshot(keys.KeyCount);
    }

    private void InvokeAuditEncrypted(short keyId, int plaintextLength, int ciphertextLength)
    {
        if (_auditObserver is null)
        {
            return;
        }
        try
        {
            _auditObserver.OnEncrypted(keyId, plaintextLength, ciphertextLength);
        }
#pragma warning disable CA1031
        catch
#pragma warning restore CA1031
        {
            // Audit observer faults must not affect the cryptographic path.
        }
    }

    private void InvokeAuditDecrypted(short keyId, int ciphertextLength, int plaintextLength)
    {
        if (_auditObserver is null)
        {
            return;
        }
        try
        {
            _auditObserver.OnDecrypted(keyId, ciphertextLength, plaintextLength);
        }
#pragma warning disable CA1031
        catch
#pragma warning restore CA1031
        {
            // Audit observer faults must not affect the cryptographic path.
        }
    }

    private void InvokeFailureHandler(string reason, short keyId, System.Exception exception)
    {
        if (_failureHandler is null)
        {
            return;
        }
        try
        {
            _failureHandler.OnDecryptionFailed(reason, keyId, exception);
        }
#pragma warning disable CA1031 // handler is observability, not load-bearing
        catch
#pragma warning restore CA1031
        {
            // handler faults are intentionally swallowed - the underlying decryption
            // exception will still propagate to the caller below.
        }
    }

    // UTF-8 inputs up to this length are encoded into a pooled buffer instead of a freshly
    // allocated byte[], removing one plaintext heap allocation per EncryptString on the common
    // per-field path. The rented buffer holds plaintext, so it is always returned with
    // clearArray:true so no secret bytes linger in the pool. This is a transient buffer size,
    // not a wire-format constant; the produced ciphertext is byte-identical either way.
    private const int MaxPooledPlaintextChars = 8 * 1024;

    public byte[] EncryptString(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        // For larger inputs the rent/clear bookkeeping stops paying for itself versus a single
        // exact-sized allocation, so fall back to the direct encode there.
        if (plaintext.Length > MaxPooledPlaintextChars)
        {
            return EncryptInternal(Encoding.UTF8.GetBytes(plaintext));
        }

        var maxBytes = Encoding.UTF8.GetMaxByteCount(plaintext.Length);
        var rented = ArrayPool<byte>.Shared.Rent(maxBytes);
        try
        {
            var written = Encoding.UTF8.GetBytes(plaintext, 0, plaintext.Length, rented, 0);
            return EncryptInternal(rented.AsSpan(0, written));
        }
        finally
        {
            // Plaintext bytes: never leave them recoverable in a pooled buffer.
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }

    public string DecryptString(byte[] ciphertext)
        => Encoding.UTF8.GetString(DecryptInternal(ciphertext));

    public byte[] EncryptBytes(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return EncryptInternal(plaintext);
    }

    public byte[] DecryptBytes(byte[] ciphertext) => DecryptInternal(ciphertext);

    private byte[] EncryptInternal(ReadOnlySpan<byte> plaintext)
    {
        using var activity = _diag.ActivitySource.StartActivity("OrionVault.Encrypt", ActivityKind.Internal);
        var sw = Stopwatch.GetTimestamp();
        var keyId = _keys.ActiveKeyId;
        activity?.SetTag("key_id", keyId);
        activity?.SetTag("algorithm", "aes-gcm-256");
        activity?.SetTag("payload_bytes", plaintext.Length);

        try
        {
            var key = LookupKey(keyId);
            var output = new byte[CipherFormat.HeaderSize + CipherFormat.TagSize + plaintext.Length];
            var nonce = output.AsSpan(CipherFormat.KeyIdSize, CipherFormat.NonceSize);
            RandomNumberGenerator.Fill(nonce);
            CipherFormat.WriteHeader(output, keyId, nonce);
            var tag = output.AsSpan(CipherFormat.HeaderSize, CipherFormat.TagSize);
            var body = output.AsSpan(CipherFormat.HeaderSize + CipherFormat.TagSize);

            using var aes = new AesGcm(key.Span, CipherFormat.TagSize);
            aes.Encrypt(nonce, plaintext, body, tag);

            _diag.Encryptions.Add(1,
                new KeyValuePair<string, object?>("algorithm", "aes-gcm-256"),
                new KeyValuePair<string, object?>("key_id", keyId));
            // v0.2.17: record plaintext size in bytes so operators can graph the p99
            // payload distribution. The histogram is sized in bytes (no kB scaling)
            // because the underlying type is int and small messages dominate; consumers
            // can apply downstream rebucketing if needed.
            _diag.EncryptionPayloadSize.Record(plaintext.Length);
            // v0.2.29: storage-amplification ratio (envelope bytes / plaintext bytes). The fixed
            // AES-GCM overhead makes this non-linear, so it is recorded as its own signal rather
            // than left for operators to derive. Empty plaintext is skipped because the ratio is
            // undefined (the envelope is all fixed overhead with no plaintext to amplify).
            if (plaintext.Length > 0)
            {
                _diag.CiphertextOverheadRatio.Record((double)output.Length / plaintext.Length);
            }
            // v0.2.23: audit observer notified after success, before return.
            InvokeAuditEncrypted(keyId, plaintext.Length, output.Length);
            return output;
        }
        catch (OrionVaultKeyNotFoundException)
        {
            // v0.2.26: the active key id is not registered - encryption cannot proceed.
            // More severe than a decrypt key-not-found because it blocks writes.
            _diag.EncryptionFailures.Add(1,
                new KeyValuePair<string, object?>("reason", "key_not_found"),
                new KeyValuePair<string, object?>("key_id", keyId));
            activity?.SetTag("outcome", "key_not_found");
            throw;
        }
        catch (OrionVaultConfigurationException)
        {
            // v0.2.26 fix (codex P2): a non-32-byte active key throws
            // OrionVaultConfigurationException from LookupKey BEFORE the AesGcm ctor, so
            // the CryptographicException catch below never sees it. Bad key length is
            // exactly the "crypto_error" the changelog advertises and every write fails,
            // so count it here.
            _diag.EncryptionFailures.Add(1,
                new KeyValuePair<string, object?>("reason", "crypto_error"),
                new KeyValuePair<string, object?>("key_id", keyId));
            activity?.SetTag("outcome", "crypto_error");
            throw;
        }
        catch (CryptographicException)
        {
            // v0.2.26: the AES-GCM operation itself failed (platform crypto fault). Rare
            // but write-blocking.
            _diag.EncryptionFailures.Add(1,
                new KeyValuePair<string, object?>("reason", "crypto_error"),
                new KeyValuePair<string, object?>("key_id", keyId));
            activity?.SetTag("outcome", "crypto_error");
            throw;
        }
        finally
        {
            _diag.Duration.Record(Stopwatch.GetElapsedTime(sw).TotalMilliseconds,
                new KeyValuePair<string, object?>("algorithm", "aes-gcm-256"),
                new KeyValuePair<string, object?>("operation", "encrypt"));
        }
    }

    private byte[] DecryptInternal(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        using var activity = _diag.ActivitySource.StartActivity("OrionVault.Decrypt", ActivityKind.Internal);
        var sw = Stopwatch.GetTimestamp();
        short keyId = 0;

        try
        {
            if (ciphertext.Length < CipherFormat.MinimumCiphertextLength)
                throw new OrionVaultDecryptionException(
                    $"Ciphertext length {ciphertext.Length} is below the minimum {CipherFormat.MinimumCiphertextLength}.");

            keyId = CipherFormat.ReadKeyId(ciphertext);
            activity?.SetTag("key_id", keyId);
            activity?.SetTag("algorithm", "aes-gcm-256");

            var key = LookupKey(keyId);
            var nonce = CipherFormat.ReadNonce(ciphertext);
            var tag = CipherFormat.ReadTag(ciphertext);
            var body = CipherFormat.ReadBody(ciphertext);
            var plaintext = new byte[body.Length];

            try
            {
                using var aes = new AesGcm(key.Span, CipherFormat.TagSize);
                aes.Decrypt(nonce, body, tag, plaintext);
            }
            catch (CryptographicException ex)
            {
                _diag.DecryptionFailures.Add(1,
                    new KeyValuePair<string, object?>("reason", "tampered"),
                    new KeyValuePair<string, object?>("key_id", keyId));
                // v0.2.27: an AuthenticationTagMismatchException is the specific AES-GCM signal
                // that the ciphertext failed tag verification (tamper / wrong key / corruption),
                // distinct from any other CryptographicException. Surface it on a dedicated
                // counter operators can alert on for tamper detection.
                if (ex is AuthenticationTagMismatchException)
                {
                    _diag.AuthTagFailures.Add(1, new KeyValuePair<string, object?>("key_id", keyId));
                }
                activity?.SetTag("outcome", "tampered");
                var tamperedException = new OrionVaultDecryptionException(
                    "Ciphertext failed authentication (tampered, wrong key, or corrupted).", ex);
                InvokeFailureHandler("tampered", keyId, tamperedException);
                throw tamperedException;
            }

            _diag.Decryptions.Add(1,
                new KeyValuePair<string, object?>("algorithm", "aes-gcm-256"),
                new KeyValuePair<string, object?>("key_id", keyId));
            // v0.2.18: record decrypted plaintext size to mirror the v0.2.17 encrypt
            // histogram so operators see both directions on one dashboard.
            _diag.DecryptionPayloadSize.Record(plaintext.Length);
            // v0.2.24: increment legacy-key counter when the decrypt resolved an older
            // key id than the current active one. Operators graph the rate to track
            // rotation progress (falling rate = rotation sweep + write traffic
            // re-encrypting rows to the new active key).
            if (keyId != _keys.ActiveKeyId)
            {
                _diag.LegacyKeyUsedOnDecrypt.Add(1,
                    new KeyValuePair<string, object?>("key_id", keyId),
                    new KeyValuePair<string, object?>("active_key_id", _keys.ActiveKeyId));
            }
            // v0.2.23: audit observer notified after success, before return.
            InvokeAuditDecrypted(keyId, ciphertext.Length, plaintext.Length);
            activity?.SetTag("outcome", "success");
            return plaintext;
        }
        catch (OrionVaultKeyNotFoundException knfEx)
        {
            InvokeFailureHandler("key_not_found", keyId, knfEx);
            _diag.DecryptionFailures.Add(1,
                new KeyValuePair<string, object?>("reason", "key_not_found"),
                new KeyValuePair<string, object?>("key_id", keyId));
            activity?.SetTag("outcome", "key_not_found");
            throw;
        }
        finally
        {
            // v0.2.28: decrypt latency now lands on the correctly-named decryption.duration_ms
            // histogram instead of being mixed into encryption.duration_ms under an
            // operation=decrypt tag. try/finally so both success and failure paths emit a sample.
            _diag.DecryptionDuration.Record(Stopwatch.GetElapsedTime(sw).TotalMilliseconds,
                new KeyValuePair<string, object?>("algorithm", "aes-gcm-256"));
        }
    }

    private ReadOnlyMemory<byte> LookupKey(short keyId)
    {
        // v0.2.21: time the key resolution round-trip so a slow backend (Key Vault,
        // KMS, database-backed IKeyProvider) surfaces independently of the AES work
        // captured by the encryption.duration histogram. try/finally so a TryGetKey
        // that THROWS still emits the duration sample - exactly the case operators
        // need to see when the key backend is failing.
        var sw = Stopwatch.GetTimestamp();
        ReadOnlyMemory<byte>? k;
        try
        {
            k = _keys.TryGetKey(keyId);
        }
        catch
        {
            _diag.KeyResolutionDuration.Record(Stopwatch.GetElapsedTime(sw).TotalMilliseconds,
                new KeyValuePair<string, object?>("outcome", "error"));
            throw;
        }
        _diag.KeyResolutionDuration.Record(Stopwatch.GetElapsedTime(sw).TotalMilliseconds,
            new KeyValuePair<string, object?>("outcome", k.HasValue && !k.Value.IsEmpty ? "hit" : "miss"));
        _diag.KeyLookups.Add(1,
            new KeyValuePair<string, object?>("key_id", keyId),
            new KeyValuePair<string, object?>("outcome", k.HasValue && !k.Value.IsEmpty ? "hit" : "miss"));
        if (!k.HasValue || k.Value.IsEmpty)
        {
            _diag.KeyNotFound.Add(1, new KeyValuePair<string, object?>("key_id", keyId));
            throw new OrionVaultKeyNotFoundException(keyId);
        }
        if (k.Value.Length != KeyLengthBytes)
            throw new OrionVaultConfigurationException(
                $"Key {keyId} is {k.Value.Length} bytes; expected {KeyLengthBytes}.");
        return k.Value;
    }
}
