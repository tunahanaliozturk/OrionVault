namespace Moongazing.OrionVault.Benchmarks;

using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;

/// <summary>
/// Measures base64 transport encoding of the ciphertext envelope. The on-disk layout is
/// raw bytes [keyId:2 | nonce:12 | tag:16 | ciphertext:N], but consumers that persist to a
/// text column or ship the envelope over JSON pay a base64 encode on write and a decode on
/// read. This isolates that envelope-codec cost from the AES work so its contribution to a
/// text-column workload is visible. The fixed 30-byte AES-GCM overhead means small payloads
/// carry a proportionally larger base64 cost, which is why payload size is parameterized.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net80)]
[SimpleJob(RuntimeMoniker.Net90)]
public class EnvelopeEncodingBenchmarks
{
    private OrionVaultDiagnostics _diagnostics = null!;
    private byte[] _envelope = null!;
    private string _base64Envelope = null!;

    [Params(16, 256, 4096)]
    public int PayloadBytes { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _diagnostics = new OrionVaultDiagnostics();
        IEncryptor encryptor = OrionVaultEncryptor.Create(new BenchmarkKeyProvider(), _diagnostics);

        var plaintext = new byte[PayloadBytes];
        RandomNumberGenerator.Fill(plaintext);
        _envelope = encryptor.EncryptBytes(plaintext);
        _base64Envelope = Convert.ToBase64String(_envelope);
    }

    [GlobalCleanup]
    public void Cleanup() => _diagnostics.Dispose();

    [Benchmark(Baseline = true)]
    public string EncodeEnvelopeToBase64() => Convert.ToBase64String(_envelope);

    [Benchmark]
    public byte[] DecodeEnvelopeFromBase64() => Convert.FromBase64String(_base64Envelope);
}
