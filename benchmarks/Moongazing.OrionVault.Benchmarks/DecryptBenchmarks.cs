namespace Moongazing.OrionVault.Benchmarks;

using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;

/// <summary>
/// Measures the decrypt hot path: header parse, key resolution, and the AES-256-GCM open
/// (authentication-tag verification plus plaintext copy), across the same column sizes as
/// <see cref="EncryptBenchmarks"/>. Ciphertexts are produced once in setup so only the
/// decrypt work is timed. Both the raw-byte and UTF-8 string paths are covered.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net80)]
[SimpleJob(RuntimeMoniker.Net90)]
public class DecryptBenchmarks
{
    private OrionVaultDiagnostics _diagnostics = null!;
    private IEncryptor _encryptor = null!;
    private byte[] _cipherFromBytes = null!;
    private byte[] _cipherFromString = null!;

    [Params(16, 256, 4096)]
    public int PayloadBytes { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _diagnostics = new OrionVaultDiagnostics();
        _encryptor = OrionVaultEncryptor.Create(new BenchmarkKeyProvider(), _diagnostics);

        var plaintextBytes = new byte[PayloadBytes];
        RandomNumberGenerator.Fill(plaintextBytes);
        _cipherFromBytes = _encryptor.EncryptBytes(plaintextBytes);

        var sb = new StringBuilder(PayloadBytes);
        for (var i = 0; i < PayloadBytes; i++)
        {
            sb.Append((char)('a' + (i % 26)));
        }
        _cipherFromString = _encryptor.EncryptString(sb.ToString());
    }

    [GlobalCleanup]
    public void Cleanup() => _diagnostics.Dispose();

    [Benchmark(Baseline = true)]
    public byte[] DecryptBytes() => _encryptor.DecryptBytes(_cipherFromBytes);

    [Benchmark]
    public string DecryptString() => _encryptor.DecryptString(_cipherFromString);
}
