# OrionVault Benchmarks

A [BenchmarkDotNet](https://benchmarkdotnet.org/) suite for the OrionVault AES-256-GCM core
lives at `benchmarks/Moongazing.OrionVault.Benchmarks`. It measures the pure cryptographic
hot paths against an in-memory key provider. No database, AWS KMS, or Azure Key Vault is
touched, so the numbers reflect the encryptor and the envelope codec in isolation rather
than any backing store or network round trip.

No measured results are committed to this file. Throughput depends heavily on CPU, .NET
runtime, and the AES-NI / VAES hardware path, so any figure here would be misleading on a
different machine. Run the suite locally and read the BenchmarkDotNet artifacts.

## What is measured

All benchmarks build an `IEncryptor` via the public `OrionVaultEncryptor.Create` factory
over an in-memory `IKeyProvider` that holds a single randomly generated 256-bit key. Every
crypto benchmark is parameterized by plaintext size at 16, 256, and 4096 bytes to model a
short token, a typical field, and a small blob. The fixed 30-byte AES-GCM envelope overhead
(2-byte key id, 12-byte nonce, 16-byte tag) means the per-call cost is non-linear across
those sizes, which is why size is a parameter rather than a single fixed input.

| Benchmark class | Method(s) | Hot path measured |
| --- | --- | --- |
| `EncryptBenchmarks` | `EncryptBytes`, `EncryptString` | Nonce generation, header write, AES-256-GCM seal. The string variant adds the UTF-8 encode that the EF string value converter performs. |
| `DecryptBenchmarks` | `DecryptBytes`, `DecryptString` | Header parse, key resolution, AES-256-GCM open with authentication-tag verification and plaintext copy. The string variant adds the UTF-8 decode. |
| `RoundTripBenchmarks` | `BytesRoundTrip`, `StringRoundTrip` | A full encrypt-then-decrypt cycle, i.e. the cost one encrypted column pays across a single write and a single read. |
| `EnvelopeEncodingBenchmarks` | `EncodeEnvelopeToBase64`, `DecodeEnvelopeFromBase64` | Base64 transport encoding and decoding of the ciphertext envelope, isolated from the AES work, for consumers persisting to a text column or shipping the envelope over JSON. |

Each class is decorated with `[MemoryDiagnoser]` so allocated bytes per operation are
reported alongside timing. Each runs under two jobs, `RuntimeMoniker.Net80` and
`RuntimeMoniker.Net90`, so the .NET 8 and .NET 9 crypto paths can be compared side by side.

## Running

```bash
dotnet run -c Release --project benchmarks/Moongazing.OrionVault.Benchmarks
```

Pass a filter to run a subset, for example a single class:

```bash
dotnet run -c Release --project benchmarks/Moongazing.OrionVault.Benchmarks -- --filter "*EncryptBenchmarks*"
```

List every discovered benchmark without running them:

```bash
dotnet run -c Release --project benchmarks/Moongazing.OrionVault.Benchmarks -- --list flat
```

Results are written to `BenchmarkDotNet.Artifacts/results/` next to the working directory.
The two-job configuration requires the .NET 8 and .NET 9 runtimes to be installed for a
full run; use `--runtimes net8.0` or `--runtimes net9.0` to restrict to one.
