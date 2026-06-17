namespace Moongazing.OrionVault.Benchmarks;

using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;

/// <summary>
/// Measures the encrypt hot path: nonce generation, header write, and the AES-256-GCM
/// seal, across representative column sizes (16 B token, 256 B field, 4 KB blob). Both the
/// raw-byte path (<see cref="IEncryptor.EncryptBytes"/>) and the UTF-8 string path
/// (<see cref="IEncryptor.EncryptString"/>, the EF string value-converter hot path) are
/// measured so the UTF-8 encode overhead is visible separately from the crypto cost.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net80)]
[SimpleJob(RuntimeMoniker.Net90)]
public class EncryptBenchmarks
{
    private OrionVaultDiagnostics _diagnostics = null!;
    private IEncryptor _encryptor = null!;
    private byte[] _plaintextBytes = null!;
    private string _plaintextString = null!;

    [Params(16, 256, 4096)]
    public int PayloadBytes { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _diagnostics = new OrionVaultDiagnostics();
        _encryptor = OrionVaultEncryptor.Create(new BenchmarkKeyProvider(), _diagnostics);

        _plaintextBytes = new byte[PayloadBytes];
        RandomNumberGenerator.Fill(_plaintextBytes);

        // ASCII so PayloadBytes equals the UTF-8 byte count, keeping the string path
        // comparable to the byte path at the same payload size.
        var sb = new StringBuilder(PayloadBytes);
        for (var i = 0; i < PayloadBytes; i++)
        {
            sb.Append((char)('a' + (i % 26)));
        }
        _plaintextString = sb.ToString();
    }

    [GlobalCleanup]
    public void Cleanup() => _diagnostics.Dispose();

    [Benchmark(Baseline = true)]
    public byte[] EncryptBytes() => _encryptor.EncryptBytes(_plaintextBytes);

    [Benchmark]
    public byte[] EncryptString() => _encryptor.EncryptString(_plaintextString);
}
