# OrionVault v0.1.0 — Design Specification

**Date:** 2026-05-24
**Status:** Approved for implementation
**Target version:** 0.1.0
**Family:** Orion (sibling of OrionGuard, OrionAudit, OrionLock, OrionKey, OrionPatch)

---

## 1. Purpose

Column-level transparent data encryption at rest for EF Core. Sensitive fields (Email, IBAN, Turkish ID, phone, etc.) are stored as ciphertext in the database and decrypted automatically when read. Threat model: an attacker who obtains a database backup or steals the storage media cannot read the protected columns.

**Out of scope for v0.1.0:**
- Blob/file/stream encryption (deferred to a future package or v0.x feature).
- Searchable encrypted columns (HMAC index property convention) — v0.3 roadmap.
- Non-string/non-byte[] CLR types (int, decimal, DateTime, JSON object) — v0.3 roadmap.
- Cloud KMS providers (AWS KMS, Azure Key Vault, Windows DPAPI, HashiCorp Vault) — v0.2 / v0.4 roadmap.
- Background re-encryption hosted service — v0.2 roadmap.
- First-class multi-DbContext support — v0.2 roadmap.

**Sibling separation note (Veil):** `Moongazing.Veil` is a separate, complementary library covering PII **masking for outputs** (logs, API responses) — values look like `j***@g***.com` in serialised output but remain plaintext in storage. OrionVault covers PII **encryption for storage** — values are ciphertext on disk and plaintext only after decryption. The two are independent; a project may use one, the other, or both.

---

## 2. Package Layout

Three NuGet packages, mirroring the OrionPatch shape:

| Package | Responsibility |
|---|---|
| `Moongazing.OrionVault` | Core abstractions (`IKeyProvider`, `IEncryptor`, `IEncryptionConfigurator`), AES-256-GCM cipher implementation, in-config `StaticKeyProvider`, diagnostics (`ActivitySource` + `Meter`), Roslyn analyzer bundled as analyzer asset. **No EF Core dependency.** |
| `Moongazing.OrionVault.EntityFrameworkCore` | `EncryptedStringConverter`, `EncryptedBytesConverter`, `[Encrypted]` attribute model scanner, `IsEncrypted()` fluent extension, `IModelCustomizer` integration, DI extensions (`UseEntityFrameworkCore<TDbContext>`, `UseOrionVault`). |
| `Moongazing.OrionVault.Testing` | `TestKeyProvider` (deterministic), `PlaintextEncryptor` (bypass for inspection tests), `EncryptionAssertions`, `UseTestKeys()` DI extension. |

Test projects (3) and one sample app (`Moongazing.OrionVault.Sample`) complete the solution.

---

## 3. Core Abstractions

Three abstractions, each with a single responsibility. KMS provider packages in v0.2+ implement `IKeyProvider` only and require no other changes to the core.

```csharp
public interface IKeyProvider
{
    /// <summary>Currently-active key id used for all new writes.</summary>
    short ActiveKeyId { get; }

    /// <summary>Lookup a key by id. Returns null if the key id is unknown.</summary>
    ReadOnlyMemory<byte>? TryGetKey(short keyId);
}

public interface IEncryptor
{
    /// <summary>Encrypt a UTF-8 string. Output includes key id, nonce, tag, ciphertext.</summary>
    byte[] EncryptString(string plaintext);

    /// <summary>Decrypt to UTF-8 string. Reads key id from ciphertext prefix.</summary>
    string DecryptString(byte[] ciphertext);

    /// <summary>Encrypt a raw byte[] payload. Output includes key id, nonce, tag, ciphertext.</summary>
    byte[] EncryptBytes(byte[] plaintext);

    /// <summary>Decrypt to raw byte[]. Reads key id from ciphertext prefix.</summary>
    byte[] DecryptBytes(byte[] ciphertext);
}

public interface IEncryptionConfigurator
{
    /// <summary>
    /// Called from <see cref="IModelCustomizer.Customize"/>. Scans the model for
    /// [Encrypted] attributes and IsEncrypted() fluent annotations, then attaches
    /// value converters to each marked property.
    /// </summary>
    void Configure(ModelBuilder modelBuilder);
}
```

`IEncryptor` is **stateless** and registered as a singleton. `IKeyProvider` is also a singleton (in v0.1.0 the keys are static config; in v0.2 KMS providers may cache lookups internally but the registration shape does not change).

---

## 4. Cipher Format

Every encrypted column value on disk has this layout:

```
┌────────┬──────────────┬───────────┬──────────────────┐
│ keyId  │ nonce        │ auth tag  │ ciphertext       │
│ 2 byte │ 12 byte      │ 16 byte   │ N byte           │
└────────┴──────────────┴───────────┴──────────────────┘
       └─── total fixed overhead: 30 bytes ────┘
```

- **`keyId` (2 bytes, big-endian uint16):** identifies which key decrypts this value. Supports up to 65,535 distinct keys per host — well above any realistic rotation scenario.
- **`nonce` (12 bytes):** AES-GCM-standard nonce length. Filled via `RandomNumberGenerator.Fill(span)` on every encryption call. The (key, nonce) pair MUST never repeat for AES-GCM security; with random 12-byte nonces the collision probability is below 2⁻⁴⁸ at billion-write scale, which is safe for any practical column-encryption workload.
- **`auth tag` (16 bytes):** GCM authentication tag. Detects tampering (any bit flip in ciphertext or tag itself causes decryption to fail).
- **`ciphertext` (N bytes):** AES-GCM output. Length equals the plaintext length.

**Empty string:** `""` is encrypted normally, producing a 30-byte value (overhead + 0-byte ciphertext). Round-trips back to `""`.

**`null`:** stored as SQL `NULL`. Encryption is not invoked. Decryption is not invoked. EF Core's existing nullability handling applies unchanged.

---

## 5. Key Rotation

Multi-key read, single-key write.

```csharp
services.AddOrionVault(o =>
{
    o.UseStaticKeys(k =>
    {
        k.Add(keyId: 1, base64Key: configuration["Vault:Key1"]!);  // legacy, read only
        k.Add(keyId: 2, base64Key: configuration["Vault:Key2"]!);  // current
    });
    o.ActiveKeyId = 2;
});
```

- **Write path:** Always uses `ActiveKeyId` (= 2). Ciphertext is prefixed with `0x00 0x02`.
- **Read path:** Reads the first 2 bytes of the ciphertext, calls `IKeyProvider.TryGetKey(keyId)`, decrypts with the returned key.
- **Re-encryption (draining a retired key):** v0.1.0 is manual. The developer runs a one-off maintenance script (`UPDATE Users SET Email = Email`) which causes EF Core's value converter to round-trip every value through `IEncryptor`, re-encrypting with `ActiveKeyId`. Once no rows remain referencing the old key, the legacy `keys.Add(keyId: 1, ...)` line is removed from configuration.
- **v0.2 roadmap:** `OrionVaultReencryptionHostedService` performs the same drain in the background, in batches, with progress logging.

**Bounds:** `ActiveKeyId` must be one of the registered keys. If not, `AddOrionVault` throws `OrionVaultConfigurationException` at startup. `keyId` range is `1..65535` (id `0` is reserved as a future sentinel).

---

## 6. Configuration API

Three styles, all interchangeable, all may coexist in one DbContext.

### 6.1 `[Encrypted]` attribute (POCO-style)

```csharp
using Moongazing.OrionVault.EntityFrameworkCore;

public class User
{
    public Guid Id { get; set; }
    public string Username { get; set; } = null!;

    [Encrypted]
    public string Email { get; set; } = null!;

    [Encrypted]
    public string? Phone { get; set; }

    [Encrypted]
    public byte[]? IdScanThumbnail { get; set; }
}
```

`[Encrypted]` is valid on `string` and `byte[]` properties only. Other CLR types produce analyzer error `OV0001` at compile time.

### 6.2 Fluent configuration (POCO stays clean)

```csharp
public class AppDbContext(DbContextOptions<AppDbContext> opt) : DbContext(opt)
{
    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>().Property(u => u.Email).IsEncrypted();
        b.Entity<User>().Property(u => u.Phone).IsEncrypted();
    }
}
```

`IsEncrypted()` is defined as an extension on `PropertyBuilder<string>` and `PropertyBuilder<byte[]>`. Other generic arguments will not compile (no extension match).

### 6.3 DI and DbContext wiring

```csharp
// Program.cs
builder.Services
    .AddOrionVault(o =>
    {
        o.UseStaticKeys(k =>
            k.Add(keyId: 1, base64Key: builder.Configuration["Vault:Key1"]!));
        o.ActiveKeyId = 1;
    })
    .UseEntityFrameworkCore<AppDbContext>();

builder.Services.AddDbContext<AppDbContext>((sp, opt) =>
{
    opt.UseSqlServer(builder.Configuration.GetConnectionString("Db"));
    opt.UseOrionVault(sp);
});
```

**`AddOrionVault(Action<OrionVaultOptions>)`** returns an `OrionVaultBuilder` (mirroring `OrionPatchBuilder`) on which the other extensions chain. It registers:
- `IEncryptor` (singleton, the AES-GCM cipher)
- `IKeyProvider` (singleton, populated from `OrionVaultOptions.UseStaticKeys`)
- `OrionVaultDiagnostics` (singleton; owns `ActivitySource` and `Meter`)

**`UseEntityFrameworkCore<TDbContext>()`** additionally registers:
- `IEncryptedValueConverterFactory` (singleton)
- `IEncryptionConfigurator` (singleton)
- `OrionVaultModelCustomizer` (singleton, decorates EF Core's default `IModelCustomizer` for `TDbContext`)

**`UseOrionVault(IServiceProvider)`** is called inside the `AddDbContext((sp, opt) => ...)` overload to attach OrionVault's model customizer to the DbContext options. Required because EF Core 8 does not expose an implicit way to do this from a service-collection-level extension. Same pattern as OrionPatch's `UseOrionPatch`.

### 6.4 Multi-DbContext constraint (v0.1.0)

`UseEntityFrameworkCore<TDbContext>()` may be called for exactly one DbContext per host in v0.1.0. Calling it twice registers duplicate factories; the second call's `IEncryptionConfigurator` wins and the first DbContext's encrypted columns become misconfigured. XML documentation on `UseEntityFrameworkCore` warns about this explicitly. First-class multi-DbContext support is v0.2 roadmap.

### 6.5 Null and empty value behaviour

| Input | Stored | Read back |
|---|---|---|
| `null` (string/byte[]) | SQL `NULL` | `null` |
| `""` (empty string) | 30-byte ciphertext (overhead + 0-byte body) | `""` |
| `new byte[0]` | 30-byte ciphertext (overhead + 0-byte body) | `new byte[0]` |
| `"hello"` | 35 bytes (30 overhead + 5 body) | `"hello"` |

---

## 7. EF Core Integration Internals

### 7.1 Value converters

```csharp
internal sealed class EncryptedStringConverter : ValueConverter<string, byte[]>
{
    public EncryptedStringConverter(IEncryptor encryptor)
        : base(
            v => encryptor.EncryptString(v),
            v => encryptor.DecryptString(v))
    { }
}

internal sealed class EncryptedBytesConverter : ValueConverter<byte[], byte[]>
{
    public EncryptedBytesConverter(IEncryptor encryptor)
        : base(
            v => encryptor.EncryptBytes(v),
            v => encryptor.DecryptBytes(v))
    { }
}
```

The converter instances are created once by `IEncryptedValueConverterFactory` and cached. Because `IEncryptor` is a singleton, capturing it in the converter lambda is safe.

### 7.2 Model customizer (auto-wiring)

```csharp
internal sealed class OrionVaultModelCustomizer : IModelCustomizer
{
    private readonly IModelCustomizer _inner;     // EF Core's default customizer
    private readonly IEncryptionConfigurator _configurator;

    public OrionVaultModelCustomizer(
        IModelCustomizer inner,
        IEncryptionConfigurator configurator)
    {
        _inner = inner;
        _configurator = configurator;
    }

    public void Customize(ModelBuilder modelBuilder, DbContext context)
    {
        _inner.Customize(modelBuilder, context);   // let EF Core configure first
        _configurator.Configure(modelBuilder);     // then attach our converters
    }
}
```

`IEncryptionConfigurator.Configure` iterates `modelBuilder.Model.GetEntityTypes()` and for each property checks:

1. **Annotation present:** `propertyBuilder.HasAnnotation("OrionVault:Encrypted", true)` was called via `IsEncrypted()`. → encrypt.
2. **Attribute present:** the CLR property has `[Encrypted]`. → encrypt.
3. Otherwise: skip.

If a property is marked but its `ClrType` is not `string` or `byte[]`, `OrionVaultConfigurationException` is thrown during model build (never at runtime).

### 7.3 Database schema effect

Encrypted columns are mapped to the provider's native blob type:

| Provider | Type |
|---|---|
| SqlServer | `varbinary(MAX)` |
| Postgres  | `bytea` |
| SQLite    | `BLOB` |
| MySQL     | `LONGBLOB` |
| Oracle    | `BLOB` |

This change is applied automatically by the value converter; the developer does not need to call `.HasColumnType(...)`. Migrating an existing `nvarchar(...)` plaintext column to encrypted form is a breaking schema change (column type becomes blob) and the developer must write a migration that copies the plaintext into the new column shape — documented in the README "Migrating existing plaintext columns" section.

### 7.4 Query semantics

LINQ queries that read encrypted columns work transparently:

```csharp
var user = await db.Users.FirstAsync(u => u.Id == userId);
Console.WriteLine(user.Email);   // decrypted, plaintext "a@b.com"
```

LINQ queries that **compare** encrypted columns in a WHERE clause silently return zero rows (the ciphertext on disk never equals the literal plaintext on the right-hand side). v0.1.0 ships a Roslyn analyzer that warns at compile time when this pattern is detected (`OV0002`). Searchable encrypted columns (HMAC index pattern) are documented in the README as the recommended mitigation; v0.3 roadmap is to ship a first-class API for this.

`OrderBy` and `GroupBy` against encrypted columns produce analyzer info diagnostic `OV0003` because they execute client-side after decryption — slow on large result sets but functionally correct.

---

## 8. Roslyn Analyzer

Bundled in the `Moongazing.OrionVault` NuGet under the standard `analyzers/dotnet/cs/` path. Installs automatically with the package; no extra setup.

| ID | Severity | Trigger | Message |
|---|---|---|---|
| `OV0001` | Error | `[Encrypted]` on a non-`string`, non-`byte[]` property. | `[Encrypted] only supports string or byte[] properties. Property '{name}' has type '{type}'.` |
| `OV0002` | Warning | A `Where`/`FirstOrDefault`/`Single` predicate compares an encrypted property to a literal or a captured variable using `==` or `!=`. | `Comparing encrypted column '{property}' to a value in a LINQ query always returns false. Use a separate HMAC index column for searchable encrypted values, or fetch and filter in memory.` |
| `OV0003` | Info | `OrderBy`/`OrderByDescending`/`GroupBy` against an encrypted property. | `Ordering or grouping by encrypted column '{property}' executes client-side after decryption; large result sets will be slow.` |

**Detection mechanism:** the analyzer registers a `CompilationStartAction` that scans for `[Encrypted]` attribute usages and for `IsEncrypted()` invocation expressions, producing a `HashSet<ISymbol>` of encrypted properties for the compilation. It then registers an `OperationAction<IInvocationOperation>` that inspects LINQ method invocations against `IQueryable<T>`, walking the predicate expression tree to find offending comparisons.

**Suppression:** developers may suppress individual cases with `[SuppressMessage("OrionVault", "OV0002")]` or `#pragma warning disable OV0002` when the false-result semantics are intentional.

---

## 9. Telemetry

`OrionVaultDiagnostics` exposes one `ActivitySource` and one `Meter`, both named `Moongazing.OrionVault`.

**ActivitySource spans:**
- `OrionVault.Encrypt` — created around each `IEncryptor.EncryptString`/`EncryptBytes` call. Tags: `key_id`, `algorithm` (`aes-gcm-256`), `payload_bytes`.
- `OrionVault.Decrypt` — created around each `DecryptString`/`DecryptBytes` call. Tags as above, plus `outcome` (`success` | `tampered` | `key_not_found`).

**Meter instruments:**

| Instrument | Type | Unit | Tags |
|---|---|---|---|
| `orionvault.encryptions` | Counter<long> | `{operations}` | `algorithm`, `key_id` |
| `orionvault.decryptions` | Counter<long> | `{operations}` | `algorithm`, `key_id` |
| `orionvault.decryption.failures` | Counter<long> | `{operations}` | `reason` (`tampered`, `key_not_found`) |
| `orionvault.key_lookups` | Counter<long> | `{operations}` | `key_id`, `outcome` (`hit`, `miss`) |
| `orionvault.key_not_found` | Counter<long> | `{operations}` | `key_id` |
| `orionvault.encryption.duration_ms` | Histogram<double> | `ms` | `algorithm`, `operation` (`encrypt`, `decrypt`) |

Counters total **5**, histograms total **1**, matching the OrionPatch shape (5+1).

All logging uses `[LoggerMessage]` source-generated logging to satisfy CA1848.

---

## 10. Error Handling

OrionVault wraps BCL crypto exceptions in two domain-specific exception types so consumers catch a single hierarchy:

| Exception | Thrown when |
|---|---|
| `OrionVaultConfigurationException` | At startup or model build: invalid key bytes, duplicate key id, `ActiveKeyId` not registered, `[Encrypted]` on unsupported type, `UseEntityFrameworkCore<>()` called twice (warning logged, no throw to preserve startup). |
| `OrionVaultDecryptionException` | At runtime decrypt: tampered ciphertext (wrapped `AuthenticationTagMismatchException`), malformed ciphertext (length < 30, invalid key id format), `IKeyProvider` returned `null` for the embedded key id (`OrionVaultKeyNotFoundException`, derived from `OrionVaultDecryptionException`). |

A failed decryption is **never** silently translated to `null` or empty — it always throws so the consuming code can react.

---

## 11. Testing Package (`Moongazing.OrionVault.Testing`)

Mirrors OrionPatch.Testing in purpose: lets consumers test production code paths without configuring real key material.

```csharp
// Deterministic test key provider — fixed 32-byte zero key by default
public sealed class TestKeyProvider : IKeyProvider
{
    public static TestKeyProvider Default { get; }     // keyId 1, zero key, Active=1

    public TestKeyProvider(short activeKeyId = 1);
    public void Add(short keyId, ReadOnlyMemory<byte> key);
    public short ActiveKeyId { get; }
    public ReadOnlyMemory<byte>? TryGetKey(short keyId);
}

// Bypass encryption entirely — plaintext stored as UTF-8 bytes with the
// standard 30-byte header but identity body. For tests that inspect raw values.
public sealed class PlaintextEncryptor : IEncryptor { ... }

// Assertion helpers
public static class EncryptionAssertions
{
    public static void IsEncrypted(byte[] columnValue);
    public static short ReadKeyId(byte[] columnValue);
    public static void IsEncryptedWithKey(byte[] columnValue, short expectedKeyId);
}

// DI extension
public static class OrionVaultTestingBuilderExtensions
{
    public static OrionVaultBuilder UseTestKeys(this OrionVaultBuilder builder, short activeKeyId = 1);
}
```

Example test:

```csharp
[Fact]
public async Task User_email_is_encrypted_at_rest()
{
    var services = new ServiceCollection()
        .AddDbContext<AppDbContext>(o => o.UseSqlite("Data Source=:memory:"))
        .AddOrionVault().UseTestKeys()
        .UseEntityFrameworkCore<AppDbContext>()
        .BuildServiceProvider();

    using var scope = services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
    db.Users.Add(new User { Email = "a@b.com" });
    await db.SaveChangesAsync();

    var rawEmail = await db.Database
        .SqlQuery<byte[]>($"SELECT Email FROM Users")
        .SingleAsync();

    EncryptionAssertions.IsEncryptedWithKey(rawEmail, expectedKeyId: 1);
}
```

---

## 12. Sample App (`Moongazing.OrionVault.Sample`)

Single-TFM (`net8.0`) console application using SQLite, demonstrates write → raw-bytes inspection → decrypted round-trip.

```csharp
// Program.cs (~50 lines)
var services = new ServiceCollection()
    .AddLogging(b => b.AddConsole())
    .AddDbContext<SampleDbContext>(o => o.UseSqlite("Data Source=sample.db"))
    .AddOrionVault(o =>
    {
        o.UseStaticKeys(k =>
            k.Add(keyId: 1, base64Key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        o.ActiveKeyId = 1;
    })
    .UseEntityFrameworkCore<SampleDbContext>()
    .BuildServiceProvider();

using var scope = services.CreateScope();
var db = scope.ServiceProvider.GetRequiredService<SampleDbContext>();
db.Database.EnsureCreated();

db.Customers.Add(new Customer
{
    Id = Guid.NewGuid(),
    FullName = "Ali Veli",
    Email = "ali@example.com",
    IbanLast4 = "1234"
});
await db.SaveChangesAsync();
Console.WriteLine("Yazıldı.");

var raw = await db.Database
    .SqlQuery<byte[]>($"SELECT Email FROM Customers")
    .SingleAsync();
Console.WriteLine($"Raw bytes in DB (first 6): {Convert.ToHexString(raw[..6])}");

var roundtrip = await db.Customers.FirstAsync();
Console.WriteLine($"Decrypted Email: {roundtrip.Email}");
```

Expected output:

```
Yazıldı.
Raw bytes in DB (first 6): 0001<random-nonce-prefix>
Decrypted Email: ali@example.com
```

The `0001` prefix is keyId 1; the next 4 bytes are the start of the 12-byte random nonce. Demonstrates visually that the value is genuinely encrypted on disk.

---

## 13. Target Frameworks and Dependencies

```xml
<TargetFrameworks>net8.0;net9.0;net10.0</TargetFrameworks>
```

`net8.0` is the minimum because `System.Security.Cryptography.AesGcm` and `RandomNumberGenerator.Fill(span)` are BCL-provided from .NET 8. The sample app targets `net8.0` only to keep build times short.

| Package | Dependency | Version | Reason |
|---|---|---|---|
| `Moongazing.OrionVault` | (none) | — | BCL only: `System.Security.Cryptography`, `System.Diagnostics.Metrics`, `System.Diagnostics.DiagnosticSource` (transitive). |
| `Moongazing.OrionVault` (analyzer asset) | `Microsoft.CodeAnalysis.CSharp` | 4.11.0 | Roslyn analyzer compilation. Analyzer DLL is ship-only, not a runtime dependency. |
| `Moongazing.OrionVault.EntityFrameworkCore` | `Microsoft.EntityFrameworkCore` | 8.0.10 | Value converters, `IModelCustomizer`. |
| | `Moongazing.OrionVault` | project ref | core |
| `Moongazing.OrionVault.Testing` | `Moongazing.OrionVault` | project ref | `TestKeyProvider`, `PlaintextEncryptor` |
| `Moongazing.OrionVault.Sample` | `Microsoft.Data.Sqlite` | (existing in family Directory.Packages.props) | demo DB |
| | `Moongazing.OrionVault.*` | project ref | demo |

Test projects (xUnit + FluentAssertions + Microsoft.Data.Sqlite) follow the OrionPatch convention exactly.

---

## 14. Solution Structure

```
Moongazing.OrionVault.sln                                  (7 entries)
├── src/
│   ├── Moongazing.OrionVault/
│   ├── Moongazing.OrionVault.EntityFrameworkCore/
│   └── Moongazing.OrionVault.Testing/
├── test/
│   ├── Moongazing.OrionVault.Tests/
│   ├── Moongazing.OrionVault.EntityFrameworkCore.Tests/
│   └── Moongazing.OrionVault.Testing.Tests/
├── sample/
│   └── Moongazing.OrionVault.Sample/
├── docs/
│   ├── logo.png
│   ├── icon.png
│   └── superpowers/
│       ├── specs/
│       └── plans/
├── .github/workflows/
│   ├── ci.yml
│   └── release.yml
├── Directory.Packages.props
├── Directory.Build.props
├── README.md
├── ROADMAP.md
├── CHANGELOG.md
└── LICENSE
```

---

## 15. CI/CD and Release

Cloned from OrionPatch's `release.yml`:

- Push tag `v*.*.*` → workflow triggers.
- `dotnet pack -c Release` produces three `.nupkg` files.
- `dotnet nuget push ... --api-key ${{ secrets.NUGET }}` (shared org-level NuGet secret already in place).
- `gh release create` produces release notes mirroring CHANGELOG.
- After release: `main` branch protection applied via `gh api PUT branches/main/protection` (same JSON body proven on OrionLock/OrionKey/OrionPatch).
- Cross-link OrionVault in the 5 sibling READMEs (OrionGuard, OrionAudit, OrionLock, OrionKey, OrionPatch) via PRs on each (their `main`/`master` branches are protected).

---

## 16. Roadmap

```
v0.1.0 — 2026-Q2 (this release)
  Column encryption (string, byte[]) via AES-256-GCM
  Multi-key read, single-key write rotation
  [Encrypted] attribute + IsEncrypted() fluent API
  Roslyn analyzer (OV0001, OV0002, OV0003)
  Testing package
  Telemetry: ActivitySource + 5 counters + 1 histogram

v0.2 — 2026-Q4
  AWS KMS provider          (Moongazing.OrionVault.AwsKms)
  Azure Key Vault provider  (Moongazing.OrionVault.AzureKeyVault)
  Background re-encryption hosted service
  First-class multi-DbContext support

v0.3 — 2027-Q1
  Numeric / DateTime / decimal type support
  Searchable encrypted columns (HMAC index property convention)
  Migration helper (plaintext → encrypted column conversion tool)

v0.4 — 2027-Q1/Q2
  Windows DPAPI provider    (Moongazing.OrionVault.Dpapi)
  HashiCorp Vault provider  (Moongazing.OrionVault.HashiCorp)
  Per-tenant key partitioning

v1.0 — 2027-Q2
  API stabilization, public surface freeze
  Production-hardened benchmarks
  Compliance mapping (KVKK, GDPR, PCI-DSS)
```

---

## 17. Open Questions / Deferred Decisions

None blocking implementation. Items deliberately deferred (with v0.x targets) are listed in §1 "Out of scope" and §16 "Roadmap".
