namespace Moongazing.OrionVault.Benchmarks;

using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;

/// <summary>
/// Measures a full encrypt-then-decrypt round trip, which is the cost a single encrypted
/// column pays across one write and one read in an EF Core workload. The string round trip
/// mirrors what the EF string value converter does end to end (UTF-8 encode, seal, open,
/// UTF-8 decode), across the same column sizes as the one-way benchmarks.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net80)]
[SimpleJob(RuntimeMoniker.Net90)]
public class RoundTripBenchmarks
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
    public byte[] BytesRoundTrip()
        => _encryptor.DecryptBytes(_encryptor.EncryptBytes(_plaintextBytes));

    [Benchmark]
    public string StringRoundTrip()
        => _encryptor.DecryptString(_encryptor.EncryptString(_plaintextString));
}
