# OrionVault Benchmarks

> **Status: pending v0.2.0.** A dedicated `bench/Moongazing.OrionVault.Bench` project will land in the next minor release. This document outlines the scenarios we intend to measure and the comparison baselines we will report against.

## Scenarios on the roadmap

- **Encrypt single value (AES-GCM, hot path).** Inputs at 16 / 64 / 256 / 1024 / 4096 byte payloads. Expected metric: nanoseconds per call, allocated bytes. Goal: stay close to raw `AesGcm.Encrypt` and pay only the cost of the 30-byte header build.
- **Decrypt single value.** Same payload sizes, reading the [keyId | nonce | tag | ciphertext] header and dispatching to the right key. Expected metric: nanoseconds per call, allocated bytes. Goal: header parse must not allocate.
- **Value-converter round trip via EF Core.** `SaveChanges` and a tracked query on an entity with 1, 5, and 20 `[Encrypted]` columns. Expected metric: throughput in entities per second on SQLite (in-memory) and Postgres (Testcontainers). Compared against the same entity with manual `ValueConverter` instances.
- **Key lookup under contention.** Concurrent decrypts (1 / 4 / 16 threads) hitting the static key provider with 1, 16, and 128 registered keys. Expected metric: throughput. Goal: confirm the key cache stays lock-free and constant-time.
- **Cold-start cost.** First call after `AddOrionVault` registration. Expected metric: total time including DI resolution and converter discovery. Goal: under a millisecond on a warm process.
- **Mixed read / write workload.** 80 percent reads / 20 percent writes against a 100,000-row table to model a realistic banking read path. Expected metric: p50 / p99 latency.

## Why not yet?

OrionVault v0.1.0 was scoped to land the cipher format, the EF Core integration, the Roslyn analyzer, and the Testing package as one shippable unit. The encryptor is a thin wrapper over `System.Security.Cryptography.AesGcm` so we have a clear ceiling for raw throughput, but a formal harness comparing the EF Core integration overhead against a hand-rolled `ValueConverter` baseline has not been written yet. It is queued for v0.2 alongside the cloud KMS providers.

## How it will be run

```bash
cd <repo-root>
dotnet run -c Release --project bench/Moongazing.OrionVault.Bench
```

Results will land in `BenchmarkDotNet.Artifacts/results/` and a summary will be committed back to this file with each release.

## Comparison baselines

We will report OrionVault numbers next to honest baselines so readers can place them in context:

- **Raw `AesGcm.Encrypt` / `AesGcm.Decrypt`.** No converter, no header, no key lookup. Establishes the cipher ceiling.
- **Manual `ValueConverter` (per-property AES-GCM you write yourself).** No key id in the payload, no analyzer, no telemetry. Establishes how much overhead the OrionVault abstractions add over a hand-rolled implementation.
- **`EntityFrameworkCore.DataEncryption` (community package).** Closest commodity alternative. Establishes how OrionVault compares against an existing package readers may already be evaluating.

The point of the comparison is to be honest about where OrionVault sits, not to win a chart. If a manual converter is faster on a given scenario we will say so and explain why the abstraction is worth the difference, or close the gap.
