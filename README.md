<p align="center">
  <img src="docs/logo.png" alt="OrionVault" width="150" />
</p>

<h1 align="center">OrionVault</h1>

<p align="center">
  Column-level transparent data encryption at rest for EF Core. AES-256-GCM, key rotation, searchable blind index, bundled Roslyn analyzer, OpenTelemetry.
</p>

<p align="center">
  <a href="https://www.nuget.org/packages/OrionVault"><img src="https://img.shields.io/nuget/v/OrionVault?style=flat-square&color=blue" alt="NuGet" /></a>
  <a href="https://www.nuget.org/packages/OrionVault"><img src="https://img.shields.io/nuget/dt/OrionVault?style=flat-square&color=green" alt="Downloads" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="License" /></a>
  <img src="https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-purple?style=flat-square" alt="Target" />
</p>

---

## What it does

OrionVault encrypts individual EF Core columns at rest. You mark a property with `[Encrypted]` (or call `IsEncrypted()` in `OnModelCreating`); OrionVault wires a value converter that encrypts on the way to the database and decrypts on the way back. The cipher is AES-256-GCM with a key id prefix so you can rotate keys without re-encrypting historical rows up front.

The threat model is narrow and explicit: an attacker who obtains a database backup, dumps the storage volume, or reads a replica's disk cannot read the protected columns without the active key set. Plaintext exists only inside authorized application processes that hold those keys.

This is not full-database TDE. It is not key management. It is the EF Core integration layer that sits on top of `System.Security.Cryptography.AesGcm` and a pluggable `IKeyProvider`. The in-config key provider (`UseStaticKeys`) ships in the box. Key-provider integrations for AWS KMS, Azure Key Vault, GCP KMS, and HashiCorp Vault are implemented as separate `OrionVault.*` projects in the repository but are not yet published to NuGet; a DPAPI provider remains on the roadmap.

The current release is 0.4.0. Searchable encryption arrived in 0.3.0: a deterministic HMAC-SHA256 blind index (`IBlindIndexProvider`) computed alongside the randomized ciphertext, so you can run equality search over an encrypted column without decrypting it. See [Searchable encrypted columns](#searchable-encrypted-columns) below.

## How it works

EF Core sees the property as `string` (or `byte[]`); the storage column is `byte[]`. A value converter sits between the two and routes through OrionVault's encryptor on write and decryptor on read.

```mermaid
sequenceDiagram
    autonumber
    participant App as Application code
    participant Ent as Entity property<br/>(plaintext string)
    participant VC as OrionVault<br/>ValueConverter
    participant Enc as AesGcmEncryptor
    participant KP as IKeyProvider
    participant DB as Database column<br/>(byte[])

    rect rgba(224, 231, 255, 0.5)
        Note over App,DB: Write path (SaveChanges)
        App->>Ent: customer.Email = "ali@example.com"
        Ent->>VC: convert to provider value
        VC->>KP: get key for ActiveKeyId
        KP-->>VC: 32-byte key
        VC->>Enc: Encrypt(plaintext, keyId, key)
        Enc-->>VC: [keyId | nonce | tag | ciphertext]
        VC->>DB: INSERT/UPDATE varbinary
    end

    rect rgba(220, 252, 231, 0.5)
        Note over App,DB: Read path (query materialization)
        DB->>VC: row bytes
        VC->>VC: parse keyId from header
        VC->>KP: get key for keyId
        KP-->>VC: 32-byte key (may be retired)
        VC->>Enc: Decrypt(bytes, key)
        Enc-->>VC: plaintext bytes
        VC->>Ent: customer.Email = "ali@example.com"
    end
```

The on-disk layout decoded above is fixed: a two-byte big-endian key id, a 12-byte AES-GCM nonce, a 16-byte authentication tag, then the ciphertext body. The reader pulls the key id first so it can ask the key provider for the exact key that wrote the row, which is what makes online key rotation work.

```mermaid
flowchart LR
    KeyId["keyId<br/>2 bytes BE"] --> Nonce["nonce<br/>12 bytes"]
    Nonce --> Tag["tag<br/>16 bytes"]
    Tag --> Cipher["ciphertext<br/>N bytes (= len plaintext)"]

    classDef hdr fill:#dbeafe,stroke:#1e40af,color:#1e3a8a
    classDef body fill:#fce7f3,stroke:#9d174d,color:#831843
    class KeyId,Nonce,Tag hdr
    class Cipher body
```

## What's in the box

| Package | Description |
|---------|-------------|
| `OrionVault` | Core: `IEncryptor`, `IKeyProvider`, `IEncryptionConfigurator`, AES-256-GCM cipher, static key provider, searchable blind index (`IBlindIndexProvider`), telemetry. Bundles the Roslyn analyzer (`analyzers/dotnet/cs/`). |
| `OrionVault.EntityFrameworkCore` | EF Core integration: `[Encrypted]` attribute, `IsEncrypted()` fluent API, value converter factory, `IModelCustomizer` wiring, `UseOrionVault()` extension. |
| `OrionVault.Testing` | Test helpers: `AddOrionVaultForTesting()` DI extension, deterministic `TestKeyProvider`, `PlaintextEncryptor` for raw-layout tests, `EncryptionAssertions`. |
| `OrionVault.AwsKms` _(in repo, not yet on NuGet)_ | AWS KMS `IKeyProvider` — unwraps data keys from AWS Key Management Service. |
| `OrionVault.AzureKeyVault` _(in repo, not yet on NuGet)_ | Azure Key Vault `IKeyProvider` — unwraps data keys from Azure Key Vault. |
| `OrionVault.GcpKms` _(in repo, not yet on NuGet)_ | Google Cloud KMS `IKeyProvider` — unwraps data keys from GCP Key Management. |
| `OrionVault.HashiCorpVault` _(in repo, not yet on NuGet)_ | HashiCorp Vault `IKeyProvider` — unwraps data keys from HashiCorp Vault's Transit engine. |

The three published packages multi-target `net8.0` / `net9.0` / `net10.0`. The analyzer ships inside the core package; there is no separate analyzers nupkg to install. The cloud-KMS / HashiCorp provider projects listed above are implemented in the repository but are not yet published to NuGet.

## 30-second quick start

Install the two runtime packages:

```bash
dotnet add package OrionVault
dotnet add package OrionVault.EntityFrameworkCore
```

Register OrionVault and bind it to your `DbContext`:

```csharp
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;

services.AddOrionVault(o =>
{
    o.UseStaticKeys(k =>
        k.Add(keyId: 1, base64Key: Environment.GetEnvironmentVariable("ORIONVAULT_KEY_1")!));
    o.ActiveKeyId = 1;
})
.UseEntityFrameworkCore<AppDbContext>();

services.AddDbContext<AppDbContext>((sp, opt) =>
    opt.UseNpgsql(connectionString).UseOrionVault(sp));
```

Mark the columns you want encrypted:

```csharp
using Moongazing.OrionVault.EntityFrameworkCore;

public class Customer
{
    public Guid Id { get; set; }
    public string FullName { get; set; } = null!;

    [Encrypted]
    public string Email { get; set; } = null!;

    [Encrypted]
    public string IbanLast4 { get; set; } = null!;
}
```

Or use the fluent API in `OnModelCreating`:

```csharp
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    modelBuilder.Entity<Customer>().Property(c => c.Email).IsEncrypted();
    modelBuilder.Entity<Customer>().Property(c => c.IbanLast4).IsEncrypted();
}
```

That's it. `SaveChanges` writes ciphertext, queries read it back as plaintext. The column type in the database becomes `byte[]` (`varbinary` / `bytea` / `BLOB` depending on provider).

## The cipher format

Every encrypted value lives in the database as a single `byte[]` with a fixed 30-byte header followed by the ciphertext body:

```
+---------+----------+----------+--------------------+
| keyId   | nonce    | tag      | ciphertext         |
| 2 bytes | 12 bytes | 16 bytes | N bytes (= len(pt))|
| BE      |          |          |                    |
+---------+----------+----------+--------------------+
   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   30-byte fixed overhead       payload
```

- `keyId` is the big-endian 16-bit identifier of the key used to encrypt this row. The decryptor reads it first and asks `IKeyProvider` for that exact key.
- `nonce` is freshly generated per encryption via `RandomNumberGenerator`. The AES-GCM nonce reuse rule (never reuse `(key, nonce)`) is honored because every encryption draws a new nonce.
- `tag` is the 128-bit GCM authentication tag.
- `ciphertext` is the same length as the original plaintext.

A UTF-8 email like `ali@example.com` (15 bytes) becomes 45 bytes on disk: 30 header + 15 body.

## Key rotation

OrionVault supports multi-key read, single-key write. You declare every key the host might encounter; `ActiveKeyId` chooses which one is used for new writes:

```csharp
services.AddOrionVault(o =>
{
    o.UseStaticKeys(k =>
    {
        k.Add(keyId: 1, base64Key: oldKeyBase64);
        k.Add(keyId: 2, base64Key: newKeyBase64);
    });
    o.ActiveKeyId = 2;
});
```

After this configuration:

- New rows are encrypted under key 2.
- Existing rows that were written under key 1 are still decrypted correctly because key 1 is still registered.
- A row encrypted under a key that is not registered throws `OrionVaultKeyNotFoundException` on read.

To actually retire key 1, re-encrypt existing rows by running them through `SaveChanges` once (load entity, mark a tracked property modified, save). The value converter encrypts under the current `ActiveKeyId`. For bulk migration, register the background `ReEncryptionHostedService` (`UseReEncryptionService()`) together with an `IReEncryptionTarget` that enumerates and rewrites the rows for your model; the hosted service drives that target on a schedule rather than walking the table itself (the default target is a no-op).

## Searchable encrypted columns

AES-GCM is randomized: encrypting the same plaintext twice produces different ciphertext. That means SQL `WHERE Email = @p` does not work against an encrypted column. The Roslyn analyzer warns about this at compile time (`OV0002`).

v0.3.0 adds a first-class **blind index** for exactly this case. A blind index is a deterministic, keyed HMAC-SHA256 digest of a normalized value: equal plaintexts always produce equal indexes, the index cannot be reversed to the plaintext without the key, and the stored ciphertext stays randomized and non-deterministic. You store the index in a separate, non-encrypted `byte[]` column and query it with an equality predicate.

Opt in with `UseBlindIndex`, then resolve `IBlindIndexProvider` from DI:

```csharp
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;

services.AddOrionVault(o =>
{
    o.UseStaticKeys(k => k.Add(keyId: 1, base64Key: encryptionKeyBase64));
    o.ActiveKeyId = 1;

    // Index keys are independent from the encryption keys and must use different secret
    // material. Minimum 16 bytes; 32 is recommended.
    o.UseBlindIndex(b => b.Add(version: 1, base64Key: indexKeyBase64));
    o.ActiveBlindIndexVersion = 1;
})
.UseEntityFrameworkCore<AppDbContext>();
```

Add a plain `byte[]` column for the index next to the encrypted property and populate it from the provider. The provider normalizes before hashing (default: trim and invariant-lowercase), so you do not lowercase by hand:

```csharp
public class Customer
{
    public Guid Id { get; set; }

    [Encrypted]
    public string Email { get; set; } = null!;

    // Blind index token from IBlindIndexProvider.Compute(...).Bytes. Searchable,
    // irreversible, self-describing (carries its key version). NOT encrypted.
    public byte[] EmailIndex { get; set; } = null!;
}

// Write path: compute the index under the active version.
customer.Email = email;
customer.EmailIndex = index.Compute(email).Bytes;

// Read path: probe with the same provider and run an equality query server-side.
byte[] probe = index.Compute(needle).Bytes;
var hit = await db.Customers.SingleOrDefaultAsync(c => c.EmailIndex == probe);
```

`Matches(value, storedIndex)` verifies a candidate against a stored token in constant time, resolving the key version from the token itself.

### Index key rotation

Index keys are versioned, mirroring encryption key rotation: new writes use `ActiveBlindIndexVersion`, and retained older versions still match rows indexed under them. Register both versions and mark the new one active:

```csharp
o.UseBlindIndex(b =>
{
    b.Add(version: 1, base64Key: oldIndexKeyBase64); // keep so old rows still match
    b.Add(version: 2, base64Key: newIndexKeyBase64); // new key for new writes
});
o.ActiveBlindIndexVersion = 2;
```

Until a re-index sweep rewrites old rows under the active version, search must probe every retained version. `ComputeAllVersions` returns one token per version (newest first) for an OR-probe:

```csharp
var probes = index.ComputeAllVersions(needle);
var hit = await db.Customers.SingleOrDefaultAsync(
    c => c.EmailIndex == probes[0].Bytes || c.EmailIndex == probes[1].Bytes);
```

The index key should be separate from the encryption key: the blind index trades a little confidentiality (equal values become linkable) for searchability, so leaking the index key must not weaken the encryption key. A runnable end-to-end example, including the rotation OR-probe, is in [demo/Moongazing.OrionVault.Demo/BlindIndexDemo.cs](demo/Moongazing.OrionVault.Demo/BlindIndexDemo.cs).

## Roslyn analyzer

Three diagnostics ship inside the core nupkg's `analyzers/dotnet/cs/` directory. No separate install.

| Id      | Severity | Catches |
|---------|----------|---------|
| OV0001  | Error    | `[Encrypted]` on a property whose type is not `string` or `byte[]`. |
| OV0002  | Warning  | LINQ `Where`/`==` comparison against an encrypted column (always returns false). |
| OV0003  | Info     | LINQ `OrderBy` / `GroupBy` on an encrypted column (executes client-side after decryption). |

Suppress per-call site with `#pragma warning disable OV0002` when you know what you are doing (for example, fetching a single row by primary key and filtering in memory).

## Telemetry

OrionVault publishes one `ActivitySource` and one `Meter`, both named `Moongazing.OrionVault`:

- Counters: `orionvault.encryptions`, `orionvault.decryptions`, `orionvault.decryption.failures`, `orionvault.key_lookups`, `orionvault.key_not_found`.
- Histogram: `orionvault.encryption.duration_ms`.

Subscribe with the standard OpenTelemetry .NET helpers:

```csharp
using OpenTelemetry.Metrics;

services.AddOpenTelemetry().WithMetrics(m => m
    .AddMeter("Moongazing.OrionVault")
    .AddPrometheusExporter());
```

Spans wrap individual encrypt and decrypt operations and are useful when correlating slow `SaveChanges` calls or unexpected decryption failures.

## Benchmarks

See [benchmarks.md](benchmarks.md) for the scenarios we measure (encrypt and decrypt throughput across payload sizes, value-converter overhead vs. a manual `ValueConverter`, key-lookup contention) and the comparison baselines. The BenchmarkDotNet project lives at `benchmarks/Moongazing.OrionVault.Benchmarks`.

## Testing

The `Moongazing.OrionVault.Testing` package wires a deterministic key provider and the real AES-GCM encryptor for fast unit tests:

```csharp
using Moongazing.OrionVault.Testing.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;

var services = new ServiceCollection()
    .AddOrionVaultForTesting()
    .UseEntityFrameworkCore<TestDbContext>()
    .Services
    .AddDbContext<TestDbContext>((sp, opt) =>
        opt.UseSqlite("Data Source=:memory:").UseOrionVault(sp))
    .BuildServiceProvider();
```

Inspect raw column bytes with `EncryptionAssertions`:

```csharp
var raw = await db.Database.SqlQuery<byte[]>($"SELECT Email AS Value FROM Customers").SingleAsync();

EncryptionAssertions.IsEncrypted(raw);
EncryptionAssertions.IsEncryptedWithKey(raw, expectedKeyId: 1);
```

If you want to bypass real cryptography in a test that is asserting wiring rather than crypto, register `PlaintextEncryptor` instead and read the header bytes directly.

## Veil vs OrionVault

These two libraries solve adjacent but different problems and a project may use one, the other, or both:

- **`Moongazing.Veil`** masks PII in **outputs** (logs, API responses, serialized DTOs). A value like `ali@example.com` is stored as plaintext in the database and shows up as `a**@e******.com` in serialized output. The threat being mitigated is shoulder-surfing, accidental log exposure, and overly chatty error responses.

- **`Moongazing.OrionVault`** encrypts PII in **storage**. The value is ciphertext on disk; the application sees plaintext after the value converter decrypts it. The threat being mitigated is a leaked backup, a stolen disk, or unauthorized direct database access.

Veil does not protect against a database leak. OrionVault does not protect against a chatty log statement. Use Veil for what humans see, use OrionVault for what disks hold.

## How it compares

| Feature                                | OrionVault | EntityFrameworkCore.DataEncryption | Manual `ValueConverter` | AspNetCore.DataProtection |
|----------------------------------------|:----------:|:----------------------------------:|:-----------------------:|:-------------------------:|
| AES-256-GCM (AEAD)                     | Yes        | AES-CBC by default                 | You choose              | Yes                       |
| Key rotation (multi-read, single-write)| Yes        | Partial                            | You build               | Yes                       |
| Per-row key id in ciphertext           | Yes        | No                                 | You build               | Yes (in payload)          |
| `[Encrypted]` attribute                | Yes        | Yes                                | -                       | -                         |
| Fluent `IsEncrypted()` API             | Yes        | Yes                                | -                       | -                         |
| Roslyn analyzer (type + query)         | Yes        | No                                 | -                       | -                         |
| OpenTelemetry counters and spans       | Yes        | No                                 | No                      | Limited                   |
| Test helpers package                   | Yes        | No                                 | -                       | -                         |
| Target frameworks                      | net8/9/10  | net6+                              | -                       | net6+                     |
| Designed for EF Core specifically      | Yes        | Yes                                | Yes                     | No                        |
| Cloud KMS providers                    | In repo    | No                                 | -                       | Via extensions            |

OrionVault is not the only column-encryption story in the .NET ecosystem; it is the one that ships an analyzer, telemetry, and a Testing package out of the box, with a deliberately small API surface. If you already have a working `EntityFrameworkCore.DataEncryption` setup and are happy with it, there is no urgent reason to migrate.

## Orion family

OrionVault is one of several standalone .NET libraries. None depend on another at runtime.

- [OrionGuard](https://github.com/tunahanaliozturk/OrionGuard) - input validation, guard clauses, DDD primitives.
- [OrionAudit](https://github.com/tunahanaliozturk/OrionAudit) - EF Core audit trail with JSON Patch diffs and time-travel reconstruction.
- [OrionLock](https://github.com/tunahanaliozturk/OrionLock) - distributed lock primitive with auto-renewing leases.
- [OrionKey](https://github.com/tunahanaliozturk/OrionKey) - source-generated strongly-typed IDs.
- [OrionPatch](https://github.com/tunahanaliozturk/OrionPatch) - transactional outbox primitive with pluggable sinks.

Each ships separately on NuGet.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full 12-month plan. Highlights:

- v0.2 - background re-encryption hosted service (`ReEncryptionHostedService`) and multi-DbContext support shipped in the core package. AWS KMS, Azure Key Vault, GCP KMS, and HashiCorp Vault provider projects are implemented but not yet published to NuGet.
- v0.3 (shipped) - First-class searchable blind index (`IBlindIndexProvider`) with versioned key rotation.
- v0.3.x (2027-Q1) - Numeric / DateTime / decimal column types; migration helper for converting existing plaintext columns.
- v0.4 (2027-Q1/Q2) - Windows DPAPI provider, HashiCorp Vault provider, per-tenant key partitioning.
- v1.0 (2027-Q2) - Public API surface freeze and compliance documentation (KVKK, GDPR, PCI-DSS mapping).

If something on the list matters to you, open an issue with the `roadmap` label.

### See it in a real app

[Moongazing.OrionShowcase](https://github.com/tunahanaliozturk/OrionShowcase) is a production-shaped banking sample integrating all six Orion packages end-to-end. OrionVault encrypts customer PII columns (TCKN, email, phone) as bytea on Postgres. The integration test reads raw bytes directly and verifies the [keyId|nonce|tag|ciphertext] header layout. Concrete usage:

- [src/Moongazing.OrionShowcase.Infrastructure/Persistence/Configurations/CustomerConfiguration.cs](https://github.com/tunahanaliozturk/OrionShowcase/blob/main/src/Moongazing.OrionShowcase.Infrastructure/Persistence/Configurations/CustomerConfiguration.cs)
- [test/Moongazing.OrionShowcase.IntegrationTests/Scenarios/PiiEncryptionTests.cs](https://github.com/tunahanaliozturk/OrionShowcase/blob/main/test/Moongazing.OrionShowcase.IntegrationTests/Scenarios/PiiEncryptionTests.cs)

## License

MIT. See [LICENSE](LICENSE).

## Contributing

Issues and pull requests welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md) before opening one.
