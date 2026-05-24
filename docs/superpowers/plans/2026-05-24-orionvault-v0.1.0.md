# OrionVault v0.1.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Moongazing.OrionVault v0.1.0 — three NuGet packages (core + EF Core integration + Testing) that provide AES-256-GCM column encryption at rest for EF Core 8/9/10, including `[Encrypted]` attribute, `IsEncrypted()` fluent API, bundled Roslyn analyzer, key rotation (multi-key read / single-key write), and OpenTelemetry instrumentation.

**Architecture:** Layered abstractions: `IKeyProvider` (key id → 32-byte key) + `IEncryptor` (AES-GCM cipher with `[keyId|nonce|tag|ciphertext]` layout) + `IEncryptionConfigurator` (EF Core model scanner). All stateless singletons. The EF Core package adds `ValueConverter<T, byte[]>` and an `IModelCustomizer` that decorates EF Core's default to attach converters automatically. Roslyn analyzer ships in the core package's `analyzers/dotnet/cs/` slot.

**Tech Stack:** .NET 8/9/10, EF Core 8.0.10, System.Security.Cryptography.AesGcm (BCL), System.Diagnostics.Metrics, Microsoft.CodeAnalysis.CSharp 4.11 (analyzer), xUnit + FluentAssertions, Microsoft.Data.Sqlite (tests).

**Reference spec:** `docs/superpowers/specs/2026-05-24-orionvault-v0.1.0-design.md`

**Reference sibling:** OrionPatch (already shipped) — same family conventions for repo layout, CI/CD, DI, telemetry, exception hierarchy, and release process. When this plan says "match OrionPatch pattern," it means look at `c:/Users/Tunahan Ali Ozturk/OneDrive - PEAKUP/Desktop/OrionPatch/` for the working precedent.

---

## File Structure

```
src/
├── Moongazing.OrionVault/
│   ├── Abstractions/
│   │   ├── IKeyProvider.cs
│   │   ├── IEncryptor.cs
│   │   └── IEncryptionConfigurator.cs
│   ├── Internal/
│   │   ├── AesGcmEncryptor.cs
│   │   ├── StaticKeyProvider.cs
│   │   └── CipherFormat.cs
│   ├── Diagnostics/
│   │   └── OrionVaultDiagnostics.cs
│   ├── Exceptions/
│   │   ├── OrionVaultConfigurationException.cs
│   │   ├── OrionVaultDecryptionException.cs
│   │   └── OrionVaultKeyNotFoundException.cs
│   ├── Options/
│   │   ├── OrionVaultOptions.cs
│   │   └── StaticKeysBuilder.cs
│   ├── DependencyInjection/
│   │   ├── OrionVaultBuilder.cs
│   │   └── OrionVaultServiceCollectionExtensions.cs
│   └── Moongazing.OrionVault.csproj
│
├── Moongazing.OrionVault.Analyzers/                    (separate csproj, ships INSIDE OrionVault nupkg)
│   ├── EncryptedTypeAnalyzer.cs                        (OV0001)
│   ├── EncryptedQueryAnalyzer.cs                       (OV0002, OV0003)
│   └── Moongazing.OrionVault.Analyzers.csproj
│
├── Moongazing.OrionVault.EntityFrameworkCore/
│   ├── EncryptedAttribute.cs
│   ├── PropertyBuilderExtensions.cs
│   ├── Internal/
│   │   ├── EncryptedStringConverter.cs
│   │   ├── EncryptedBytesConverter.cs
│   │   ├── EncryptedValueConverterFactory.cs
│   │   ├── EncryptionConfigurator.cs
│   │   └── OrionVaultModelCustomizer.cs
│   ├── DependencyInjection/
│   │   └── OrionVaultEntityFrameworkCoreBuilderExtensions.cs
│   └── Moongazing.OrionVault.EntityFrameworkCore.csproj
│
└── Moongazing.OrionVault.Testing/
    ├── TestKeyProvider.cs
    ├── PlaintextEncryptor.cs
    ├── EncryptionAssertions.cs
    ├── DependencyInjection/
    │   └── OrionVaultTestingBuilderExtensions.cs
    └── Moongazing.OrionVault.Testing.csproj

test/
├── Moongazing.OrionVault.Tests/
├── Moongazing.OrionVault.EntityFrameworkCore.Tests/
└── Moongazing.OrionVault.Testing.Tests/

sample/
└── Moongazing.OrionVault.Sample/
    ├── Program.cs
    ├── SampleDbContext.cs
    ├── Customer.cs
    └── Moongazing.OrionVault.Sample.csproj

Repo root:
├── Moongazing.OrionVault.sln
├── Directory.Packages.props
├── Directory.Build.props
├── .gitignore
├── README.md
├── ROADMAP.md
├── CHANGELOG.md
├── LICENSE
├── docs/
│   ├── logo.png
│   ├── icon.png
│   └── superpowers/
│       ├── specs/
│       └── plans/
└── .github/workflows/
    ├── ci.yml
    └── release.yml
```

---

## Tasks Overview

| # | Task | Output |
|---|------|--------|
| 0 | Repo bootstrap | Empty solution, all 4 src + 3 test + 1 sample csproj skeletons, Directory.* props, .gitignore, CI workflows, GitHub repo created and pushed |
| 1 | Core abstractions + exceptions | `IKeyProvider`, `IEncryptor`, `IEncryptionConfigurator`, 3 exception types |
| 2 | Cipher format + AES-GCM encryptor | `CipherFormat`, `AesGcmEncryptor` with full round-trip tests |
| 3 | Options + StaticKeyProvider + DI | `OrionVaultOptions`, `StaticKeysBuilder`, `StaticKeyProvider`, `OrionVaultBuilder`, `AddOrionVault` |
| 4 | Telemetry | `OrionVaultDiagnostics`, wired into `AesGcmEncryptor`, source-generated logging |
| 5 | EF Core converters + attribute | `[Encrypted]`, `EncryptedStringConverter`, `EncryptedBytesConverter`, `EncryptedValueConverterFactory` |
| 6 | EF Core model integration | `IsEncrypted()` fluent, `EncryptionConfigurator`, `OrionVaultModelCustomizer` |
| 7 | EF Core DI wiring | `UseEntityFrameworkCore<TDbContext>`, `UseOrionVault` |
| 8 | Roslyn analyzers | `EncryptedTypeAnalyzer` (OV0001), `EncryptedQueryAnalyzer` (OV0002, OV0003), bundled into OrionVault nupkg |
| 9 | Testing package | `TestKeyProvider`, `PlaintextEncryptor`, `EncryptionAssertions`, `UseTestKeys()` |
| 10 | Sample app | Console app that writes encrypted, inspects raw bytes, decrypts |
| 11 | Documentation polish | README, per-package READMEs, ROADMAP, CHANGELOG draft |
| 12 | First release v0.1.0 | CHANGELOG finalize, tag v0.1.0, NuGet publish, branch protection, family cross-link |

---

## Task 0: Repo bootstrap

**Files:**
- Create: `Moongazing.OrionVault.sln`
- Create: `Directory.Packages.props`, `Directory.Build.props`, `.gitignore`, `LICENSE`
- Create: 8 csproj skeletons under `src/`, `test/`, `sample/`
- Create: `.github/workflows/ci.yml`, `.github/workflows/release.yml`
- Create: `README.md` (single-line placeholder, polished in Task 11)
- Create: GitHub repo `tunahanaliozturk/OrionVault`

- [ ] **Step 1: Verify working directory and existing git**

```
cd "c:/Users/Tunahan Ali Ozturk/OneDrive - PEAKUP/Desktop/OrionVault"
git log --oneline | head -3
```
Expected: shows `68e0029 docs: add OrionVault v0.1.0 design specification` (plus the plan commit if already committed).

- [ ] **Step 2: Create `.gitignore`**

Copy verbatim from OrionPatch:
```
cp "c:/Users/Tunahan Ali Ozturk/OneDrive - PEAKUP/Desktop/OrionPatch/.gitignore" .gitignore
```

- [ ] **Step 3: Create `LICENSE` (MIT)**

```
cp "c:/Users/Tunahan Ali Ozturk/OneDrive - PEAKUP/Desktop/OrionPatch/LICENSE" LICENSE
```
Then open and update the copyright line to `Copyright (c) 2026 Moongazing` (year only — keep the author).

- [ ] **Step 4: Create `Directory.Build.props`**

```xml
<Project>
  <PropertyGroup>
    <LangVersion>latest</LangVersion>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <EnforceCodeStyleInBuild>true</EnforceCodeStyleInBuild>
    <AnalysisLevel>latest</AnalysisLevel>
    <AnalysisMode>AllEnabledByDefault</AnalysisMode>
    <NoWarn>$(NoWarn);CA1014</NoWarn>
    <Authors>Moongazing</Authors>
    <Company>Moongazing</Company>
    <Copyright>Copyright (c) 2026 Moongazing</Copyright>
    <PackageLicenseExpression>MIT</PackageLicenseExpression>
    <PackageProjectUrl>https://github.com/tunahanaliozturk/OrionVault</PackageProjectUrl>
    <RepositoryUrl>https://github.com/tunahanaliozturk/OrionVault</RepositoryUrl>
    <RepositoryType>git</RepositoryType>
    <PackageTags>encryption;security;ef-core;column-encryption;aes-gcm;orion</PackageTags>
    <PackageIcon>icon.png</PackageIcon>
    <PackageReadmeFile>README.md</PackageReadmeFile>
    <Version>0.1.0</Version>
  </PropertyGroup>
  <ItemGroup Condition="'$(IsPackable)' == 'true'">
    <None Include="$(MSBuildThisFileDirectory)docs/icon.png" Pack="true" PackagePath="\" />
  </ItemGroup>
</Project>
```

- [ ] **Step 5: Create `Directory.Packages.props`**

```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Microsoft.EntityFrameworkCore" Version="8.0.10" />
    <PackageVersion Include="Microsoft.EntityFrameworkCore.Sqlite" Version="8.0.10" />
    <PackageVersion Include="Microsoft.Data.Sqlite" Version="8.0.10" />
    <PackageVersion Include="Microsoft.Extensions.DependencyInjection.Abstractions" Version="8.0.2" />
    <PackageVersion Include="Microsoft.Extensions.Logging.Abstractions" Version="8.0.2" />
    <PackageVersion Include="Microsoft.Extensions.Options" Version="8.0.2" />
    <PackageVersion Include="Microsoft.CodeAnalysis.CSharp" Version="4.11.0" />
    <PackageVersion Include="Microsoft.CodeAnalysis.CSharp.Workspaces" Version="4.11.0" />
    <PackageVersion Include="xunit" Version="2.9.2" />
    <PackageVersion Include="xunit.runner.visualstudio" Version="2.8.2" />
    <PackageVersion Include="FluentAssertions" Version="6.12.1" />
    <PackageVersion Include="Microsoft.NET.Test.Sdk" Version="17.11.1" />
    <PackageVersion Include="coverlet.collector" Version="6.0.2" />
  </ItemGroup>
</Project>
```

- [ ] **Step 6: Create empty solution + project skeletons**

```
dotnet new sln -n Moongazing.OrionVault
dotnet new classlib -n Moongazing.OrionVault -o src/Moongazing.OrionVault -f net8.0
dotnet new classlib -n Moongazing.OrionVault.Analyzers -o src/Moongazing.OrionVault.Analyzers -f netstandard2.0
dotnet new classlib -n Moongazing.OrionVault.EntityFrameworkCore -o src/Moongazing.OrionVault.EntityFrameworkCore -f net8.0
dotnet new classlib -n Moongazing.OrionVault.Testing -o src/Moongazing.OrionVault.Testing -f net8.0
dotnet new xunit -n Moongazing.OrionVault.Tests -o test/Moongazing.OrionVault.Tests -f net8.0
dotnet new xunit -n Moongazing.OrionVault.EntityFrameworkCore.Tests -o test/Moongazing.OrionVault.EntityFrameworkCore.Tests -f net8.0
dotnet new xunit -n Moongazing.OrionVault.Testing.Tests -o test/Moongazing.OrionVault.Testing.Tests -f net8.0
dotnet new console -n Moongazing.OrionVault.Sample -o sample/Moongazing.OrionVault.Sample -f net8.0
```

Remove the auto-generated `Class1.cs` from each classlib project. Delete `UnitTest1.cs` from each xunit project.

- [ ] **Step 7: Add all projects to solution**

```
dotnet sln add src/Moongazing.OrionVault/Moongazing.OrionVault.csproj
dotnet sln add src/Moongazing.OrionVault.Analyzers/Moongazing.OrionVault.Analyzers.csproj
dotnet sln add src/Moongazing.OrionVault.EntityFrameworkCore/Moongazing.OrionVault.EntityFrameworkCore.csproj
dotnet sln add src/Moongazing.OrionVault.Testing/Moongazing.OrionVault.Testing.csproj
dotnet sln add test/Moongazing.OrionVault.Tests/Moongazing.OrionVault.Tests.csproj
dotnet sln add test/Moongazing.OrionVault.EntityFrameworkCore.Tests/Moongazing.OrionVault.EntityFrameworkCore.Tests.csproj
dotnet sln add test/Moongazing.OrionVault.Testing.Tests/Moongazing.OrionVault.Testing.Tests.csproj
dotnet sln add sample/Moongazing.OrionVault.Sample/Moongazing.OrionVault.Sample.csproj
```

- [ ] **Step 8: Replace `src/Moongazing.OrionVault/Moongazing.OrionVault.csproj`**

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFrameworks>net8.0;net9.0;net10.0</TargetFrameworks>
    <IsPackable>true</IsPackable>
    <PackageId>Moongazing.OrionVault</PackageId>
    <Description>Column-level transparent data encryption at rest for EF Core. AES-256-GCM with key rotation, [Encrypted] attribute, fluent API, bundled Roslyn analyzer, and OpenTelemetry instrumentation.</Description>
    <IncludeBuildOutput>true</IncludeBuildOutput>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.Extensions.DependencyInjection.Abstractions" />
    <PackageReference Include="Microsoft.Extensions.Logging.Abstractions" />
    <PackageReference Include="Microsoft.Extensions.Options" />
  </ItemGroup>
  <!-- Bundle the analyzer assembly into this nupkg under analyzers/dotnet/cs/ -->
  <ItemGroup>
    <ProjectReference Include="..\Moongazing.OrionVault.Analyzers\Moongazing.OrionVault.Analyzers.csproj"
                      ReferenceOutputAssembly="false"
                      OutputItemType="Analyzer"
                      PrivateAssets="all" />
    <None Include="..\Moongazing.OrionVault.Analyzers\bin\$(Configuration)\netstandard2.0\Moongazing.OrionVault.Analyzers.dll"
          Pack="true"
          PackagePath="analyzers/dotnet/cs/"
          Visible="false" />
  </ItemGroup>
</Project>
```

- [ ] **Step 9: Replace `src/Moongazing.OrionVault.Analyzers/Moongazing.OrionVault.Analyzers.csproj`**

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>netstandard2.0</TargetFramework>
    <IsPackable>false</IsPackable>
    <EnforceExtendedAnalyzerRules>true</EnforceExtendedAnalyzerRules>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.CodeAnalysis.CSharp" PrivateAssets="all" />
    <PackageReference Include="Microsoft.CodeAnalysis.CSharp.Workspaces" PrivateAssets="all" />
  </ItemGroup>
</Project>
```

- [ ] **Step 10: Replace `src/Moongazing.OrionVault.EntityFrameworkCore/Moongazing.OrionVault.EntityFrameworkCore.csproj`**

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFrameworks>net8.0;net9.0;net10.0</TargetFrameworks>
    <IsPackable>true</IsPackable>
    <PackageId>Moongazing.OrionVault.EntityFrameworkCore</PackageId>
    <Description>EF Core integration for Moongazing.OrionVault: value converters, [Encrypted] attribute model scanner, IsEncrypted() fluent API, IModelCustomizer wiring, and DbContext DI extensions.</Description>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.EntityFrameworkCore" />
    <ProjectReference Include="..\Moongazing.OrionVault\Moongazing.OrionVault.csproj" />
  </ItemGroup>
</Project>
```

- [ ] **Step 11: Replace `src/Moongazing.OrionVault.Testing/Moongazing.OrionVault.Testing.csproj`**

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFrameworks>net8.0;net9.0;net10.0</TargetFrameworks>
    <IsPackable>true</IsPackable>
    <PackageId>Moongazing.OrionVault.Testing</PackageId>
    <Description>Test helpers for Moongazing.OrionVault: deterministic TestKeyProvider, PlaintextEncryptor for inspection tests, and EncryptionAssertions.</Description>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="..\Moongazing.OrionVault\Moongazing.OrionVault.csproj" />
  </ItemGroup>
</Project>
```

- [ ] **Step 12: Replace each test project csproj**

For each of the 3 test projects, the csproj should be:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <IsPackable>false</IsPackable>
    <IsTestProject>true</IsTestProject>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" />
    <PackageReference Include="xunit" />
    <PackageReference Include="xunit.runner.visualstudio" />
    <PackageReference Include="coverlet.collector" />
    <PackageReference Include="FluentAssertions" />
  </ItemGroup>
  <ItemGroup>
    <!-- Add ProjectReference to the SUT (system under test) - one per test project -->
    <!-- Moongazing.OrionVault.Tests:                       references src/Moongazing.OrionVault -->
    <!-- Moongazing.OrionVault.EntityFrameworkCore.Tests:   references src/Moongazing.OrionVault.EntityFrameworkCore + Microsoft.EntityFrameworkCore.Sqlite + Microsoft.Data.Sqlite -->
    <!-- Moongazing.OrionVault.Testing.Tests:               references src/Moongazing.OrionVault.Testing -->
  </ItemGroup>
</Project>
```

Append the matching `ProjectReference` lines to each. For the EntityFrameworkCore.Tests project also add:
```xml
<PackageReference Include="Microsoft.EntityFrameworkCore.Sqlite" />
<PackageReference Include="Microsoft.Data.Sqlite" />
```

- [ ] **Step 13: Replace `sample/Moongazing.OrionVault.Sample/Moongazing.OrionVault.Sample.csproj`**

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <IsPackable>false</IsPackable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.EntityFrameworkCore.Sqlite" />
    <PackageReference Include="Microsoft.Extensions.Logging.Console" Version="8.0.1" />
    <ProjectReference Include="..\..\src\Moongazing.OrionVault\Moongazing.OrionVault.csproj" />
    <ProjectReference Include="..\..\src\Moongazing.OrionVault.EntityFrameworkCore\Moongazing.OrionVault.EntityFrameworkCore.csproj" />
  </ItemGroup>
</Project>
```

Add `Microsoft.Extensions.Logging.Console` version 8.0.1 to `Directory.Packages.props` as well (so central-package-management does not warn).

- [ ] **Step 14: Verify build of empty solution**

Run:
```
dotnet build Moongazing.OrionVault.sln
```
Expected: builds successfully with zero errors. Warnings about empty assemblies are OK.

- [ ] **Step 15: Copy CI/release workflows from OrionPatch**

```
mkdir -p .github/workflows
cp "c:/Users/Tunahan Ali Ozturk/OneDrive - PEAKUP/Desktop/OrionPatch/.github/workflows/ci.yml" .github/workflows/ci.yml
cp "c:/Users/Tunahan Ali Ozturk/OneDrive - PEAKUP/Desktop/OrionPatch/.github/workflows/release.yml" .github/workflows/release.yml
```

Open both files and verify:
- `ci.yml`: solution name reference is `Moongazing.OrionVault.sln` (search/replace if it says `OrionPatch`).
- `release.yml`: solution name reference, package globs (`src/**/*.nupkg`), and `${{ secrets.NUGET }}` are correct.

- [ ] **Step 16: Placeholder README**

Create `README.md` with:
```markdown
# Moongazing.OrionVault

Column-level transparent data encryption at rest for EF Core.

Documentation in progress — see [ROADMAP.md](ROADMAP.md) and [docs/superpowers/specs/](docs/superpowers/specs/).

Part of the Orion family: [OrionGuard](https://github.com/tunahanaliozturk/OrionGuard), [OrionAudit](https://github.com/tunahanaliozturk/OrionAudit), [OrionLock](https://github.com/tunahanaliozturk/OrionLock), [OrionKey](https://github.com/tunahanaliozturk/OrionKey), [OrionPatch](https://github.com/tunahanaliozturk/OrionPatch).
```

The full README is written in Task 11.

- [ ] **Step 17: Commit local scaffolding**

```
git add -A
git commit -m "chore: scaffold solution, projects, build props, CI workflows"
```

- [ ] **Step 18: Create GitHub repo and push**

```
gh repo create tunahanaliozturk/OrionVault --public \
  --description "Column-level transparent data encryption at rest for EF Core. Part of the Orion family." \
  --homepage "https://www.nuget.org/packages/Moongazing.OrionVault" \
  --source . --remote origin --push
```
Expected: repo created, `main` branch pushed, `git remote -v` shows `origin → https://github.com/tunahanaliozturk/OrionVault.git`.

- [ ] **Step 19: Verify CI workflow runs green on the empty solution**

```
gh run watch
```
Expected: CI passes (just `dotnet build` and `dotnet test --no-build` on empty projects, both succeed).

---

## Task 1: Core abstractions + exceptions

**Files:**
- Create: `src/Moongazing.OrionVault/Abstractions/IKeyProvider.cs`
- Create: `src/Moongazing.OrionVault/Abstractions/IEncryptor.cs`
- Create: `src/Moongazing.OrionVault/Abstractions/IEncryptionConfigurator.cs`
- Create: `src/Moongazing.OrionVault/Exceptions/OrionVaultConfigurationException.cs`
- Create: `src/Moongazing.OrionVault/Exceptions/OrionVaultDecryptionException.cs`
- Create: `src/Moongazing.OrionVault/Exceptions/OrionVaultKeyNotFoundException.cs`
- Test: `test/Moongazing.OrionVault.Tests/Exceptions/ExceptionHierarchyTests.cs`

- [ ] **Step 1: Write the failing test for exception hierarchy**

`test/Moongazing.OrionVault.Tests/Exceptions/ExceptionHierarchyTests.cs`:
```csharp
namespace Moongazing.OrionVault.Tests.Exceptions;

using FluentAssertions;
using Moongazing.OrionVault.Exceptions;
using Xunit;

public class ExceptionHierarchyTests
{
    [Fact]
    public void OrionVaultKeyNotFoundException_is_a_DecryptionException()
    {
        var sut = new OrionVaultKeyNotFoundException(keyId: 42);

        sut.Should().BeAssignableTo<OrionVaultDecryptionException>();
        sut.KeyId.Should().Be(42);
        sut.Message.Should().Contain("42");
    }

    [Fact]
    public void OrionVaultDecryptionException_wraps_inner_exception()
    {
        var inner = new InvalidOperationException("boom");

        var sut = new OrionVaultDecryptionException("Decryption failed.", inner);

        sut.InnerException.Should().BeSameAs(inner);
        sut.Message.Should().Be("Decryption failed.");
    }

    [Fact]
    public void OrionVaultConfigurationException_carries_message()
    {
        var sut = new OrionVaultConfigurationException("Active key 9 is not registered.");

        sut.Message.Should().Contain("Active key 9");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```
dotnet test test/Moongazing.OrionVault.Tests/Moongazing.OrionVault.Tests.csproj
```
Expected: FAIL with "type or namespace 'Exceptions' does not exist".

- [ ] **Step 3: Create the three exception types**

`src/Moongazing.OrionVault/Exceptions/OrionVaultConfigurationException.cs`:
```csharp
namespace Moongazing.OrionVault.Exceptions;

/// <summary>
/// Thrown when OrionVault is misconfigured — invalid key bytes, duplicate key id,
/// <c>ActiveKeyId</c> not registered, <c>[Encrypted]</c> on an unsupported type, etc.
/// Raised at startup or model build, never at runtime decrypt.
/// </summary>
public sealed class OrionVaultConfigurationException : Exception
{
    public OrionVaultConfigurationException(string message) : base(message) { }

    public OrionVaultConfigurationException(string message, Exception innerException)
        : base(message, innerException) { }
}
```

`src/Moongazing.OrionVault/Exceptions/OrionVaultDecryptionException.cs`:
```csharp
namespace Moongazing.OrionVault.Exceptions;

/// <summary>
/// Thrown when decryption of a stored ciphertext fails. Reasons include tampered
/// ciphertext (authentication tag mismatch), malformed ciphertext (too short or
/// invalid header), or unknown key id (see <see cref="OrionVaultKeyNotFoundException"/>).
/// </summary>
public class OrionVaultDecryptionException : Exception
{
    public OrionVaultDecryptionException(string message) : base(message) { }

    public OrionVaultDecryptionException(string message, Exception innerException)
        : base(message, innerException) { }
}
```

`src/Moongazing.OrionVault/Exceptions/OrionVaultKeyNotFoundException.cs`:
```csharp
namespace Moongazing.OrionVault.Exceptions;

/// <summary>
/// Thrown when the ciphertext references a key id not present in the configured
/// <see cref="Abstractions.IKeyProvider"/>. Typical cause: a key was rotated out
/// while values encrypted with it are still in the database.
/// </summary>
public sealed class OrionVaultKeyNotFoundException : OrionVaultDecryptionException
{
    public short KeyId { get; }

    public OrionVaultKeyNotFoundException(short keyId)
        : base($"OrionVault key id {keyId} was not found in the configured IKeyProvider.")
    {
        KeyId = keyId;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

```
dotnet test test/Moongazing.OrionVault.Tests/Moongazing.OrionVault.Tests.csproj
```
Expected: 3 tests PASS.

- [ ] **Step 5: Create the three abstractions**

`src/Moongazing.OrionVault/Abstractions/IKeyProvider.cs`:
```csharp
namespace Moongazing.OrionVault.Abstractions;

/// <summary>
/// Provides 256-bit symmetric keys identified by a short key id. Implementations
/// must be thread-safe and registered as singletons. v0.1.0 ships
/// <c>StaticKeyProvider</c> (in-config base64 keys); v0.2 roadmap adds AWS KMS,
/// Azure Key Vault, and Windows DPAPI providers.
/// </summary>
public interface IKeyProvider
{
    /// <summary>
    /// The key id used for all new encryptions. Must be registered (i.e.,
    /// <see cref="TryGetKey"/>(<see cref="ActiveKeyId"/>) returns non-null).
    /// </summary>
    short ActiveKeyId { get; }

    /// <summary>
    /// Looks up a key by id. Returns <c>null</c> if the id is not registered.
    /// The returned memory must be exactly 32 bytes.
    /// </summary>
    ReadOnlyMemory<byte>? TryGetKey(short keyId);
}
```

`src/Moongazing.OrionVault/Abstractions/IEncryptor.cs`:
```csharp
namespace Moongazing.OrionVault.Abstractions;

/// <summary>
/// Encrypts and decrypts column values. The on-disk layout is
/// <c>[keyId:2 | nonce:12 | tag:16 | ciphertext:N]</c> (30-byte fixed overhead).
/// Implementations must be thread-safe and registered as singletons.
/// </summary>
public interface IEncryptor
{
    /// <summary>
    /// Encrypts a UTF-8 string. Output is the standard layout above.
    /// </summary>
    byte[] EncryptString(string plaintext);

    /// <summary>
    /// Decrypts to a UTF-8 string. Reads the key id from the first 2 bytes
    /// of <paramref name="ciphertext"/>.
    /// </summary>
    /// <exception cref="Exceptions.OrionVaultDecryptionException">
    /// Thrown on tampering, malformed input, or unknown key id.
    /// </exception>
    string DecryptString(byte[] ciphertext);

    /// <summary>
    /// Encrypts a raw byte array. Output is the standard layout above.
    /// </summary>
    byte[] EncryptBytes(byte[] plaintext);

    /// <summary>
    /// Decrypts a raw byte array. Reads the key id from the first 2 bytes
    /// of <paramref name="ciphertext"/>.
    /// </summary>
    /// <exception cref="Exceptions.OrionVaultDecryptionException">
    /// Thrown on tampering, malformed input, or unknown key id.
    /// </exception>
    byte[] DecryptBytes(byte[] ciphertext);
}
```

`src/Moongazing.OrionVault/Abstractions/IEncryptionConfigurator.cs`:
```csharp
namespace Moongazing.OrionVault.Abstractions;

using Microsoft.EntityFrameworkCore;

/// <summary>
/// Scans an EF Core model and attaches value converters to properties marked
/// with <c>[Encrypted]</c> or via <c>IsEncrypted()</c>. Invoked by
/// <c>OrionVaultModelCustomizer</c> after EF Core's default customizer.
/// </summary>
/// <remarks>
/// This interface lives in the core package (no EF Core ProjectReference would
/// otherwise be needed) because the core's <c>OrionVaultBuilder.UseEntityFrameworkCore</c>
/// pattern is the only way to wire it up — keeping the abstraction here avoids a
/// circular dependency at the type-name level. Implementations live in
/// <c>Moongazing.OrionVault.EntityFrameworkCore</c>.
/// </remarks>
public interface IEncryptionConfigurator
{
    void Configure(ModelBuilder modelBuilder);
}
```

Add EF Core PackageReference to the core csproj (required for `ModelBuilder` reference):
```xml
<!-- Add to src/Moongazing.OrionVault/Moongazing.OrionVault.csproj <ItemGroup> -->
<PackageReference Include="Microsoft.EntityFrameworkCore" />
```

Note: this is a "thin" reference — the core needs only the `ModelBuilder` type for the interface. If this feels heavy, an alternative is to define `IEncryptionConfigurator` in the EF Core package and skip the core dependency on EF Core. **Decision for v0.1.0:** keep `IEncryptionConfigurator` in the core because the `OrionVaultBuilder.UseEntityFrameworkCore` extension needs to register a configurator type into the core's DI surface. The EF Core dep on the core package is acceptable (it's a single thin assembly, no runtime cost beyond the load).

- [ ] **Step 6: Build solution to verify**

```
dotnet build Moongazing.OrionVault.sln
```
Expected: builds with zero errors, zero warnings.

- [ ] **Step 7: Commit**

```
git add src/Moongazing.OrionVault/ test/Moongazing.OrionVault.Tests/
git commit -m "feat: add core abstractions (IKeyProvider, IEncryptor, IEncryptionConfigurator) and exception hierarchy"
git push
```

---

## Task 2: Cipher format + AES-GCM encryptor

**Files:**
- Create: `src/Moongazing.OrionVault/Internal/CipherFormat.cs`
- Create: `src/Moongazing.OrionVault/Internal/AesGcmEncryptor.cs`
- Test: `test/Moongazing.OrionVault.Tests/Internal/CipherFormatTests.cs`
- Test: `test/Moongazing.OrionVault.Tests/Internal/AesGcmEncryptorTests.cs`

- [ ] **Step 1: Write the failing test for CipherFormat**

`test/Moongazing.OrionVault.Tests/Internal/CipherFormatTests.cs`:
```csharp
namespace Moongazing.OrionVault.Tests.Internal;

using FluentAssertions;
using Moongazing.OrionVault.Internal;
using Xunit;

public class CipherFormatTests
{
    [Fact]
    public void WriteHeader_writes_keyId_big_endian()
    {
        Span<byte> buffer = stackalloc byte[CipherFormat.HeaderSize];
        Span<byte> nonce = stackalloc byte[12];
        nonce.Fill(0xAA);

        CipherFormat.WriteHeader(buffer, keyId: 0x0102, nonce);

        buffer[0].Should().Be(0x01);
        buffer[1].Should().Be(0x02);
        for (int i = 0; i < 12; i++) buffer[2 + i].Should().Be(0xAA);
    }

    [Fact]
    public void ReadKeyId_round_trips_with_WriteHeader()
    {
        Span<byte> buffer = stackalloc byte[CipherFormat.HeaderSize];
        Span<byte> nonce = stackalloc byte[12];
        CipherFormat.WriteHeader(buffer, keyId: 7, nonce);

        CipherFormat.ReadKeyId(buffer).Should().Be(7);
    }

    [Fact]
    public void Constants_match_spec()
    {
        CipherFormat.KeyIdSize.Should().Be(2);
        CipherFormat.NonceSize.Should().Be(12);
        CipherFormat.TagSize.Should().Be(16);
        CipherFormat.HeaderSize.Should().Be(14);   // keyId + nonce, written before encryption
        CipherFormat.MinimumCiphertextLength.Should().Be(30);  // header + tag + 0-byte body
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```
dotnet test test/Moongazing.OrionVault.Tests/Moongazing.OrionVault.Tests.csproj --filter FullyQualifiedName~CipherFormatTests
```
Expected: FAIL — `CipherFormat` not defined.

- [ ] **Step 3: Implement CipherFormat**

`src/Moongazing.OrionVault/Internal/CipherFormat.cs`:
```csharp
namespace Moongazing.OrionVault.Internal;

using System.Buffers.Binary;

/// <summary>
/// On-disk layout: <c>[keyId:2 BE | nonce:12 | tag:16 | ciphertext:N]</c>.
/// Total fixed overhead is 30 bytes; minimum legal ciphertext length is 30.
/// </summary>
internal static class CipherFormat
{
    public const int KeyIdSize = 2;
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int HeaderSize = KeyIdSize + NonceSize;            // 14, written pre-encryption
    public const int MinimumCiphertextLength = HeaderSize + TagSize; // 30

    public static void WriteHeader(Span<byte> destination, short keyId, ReadOnlySpan<byte> nonce)
    {
        if (destination.Length < HeaderSize)
            throw new ArgumentException($"Destination must be at least {HeaderSize} bytes.", nameof(destination));
        if (nonce.Length != NonceSize)
            throw new ArgumentException($"Nonce must be exactly {NonceSize} bytes.", nameof(nonce));

        BinaryPrimitives.WriteInt16BigEndian(destination[..KeyIdSize], keyId);
        nonce.CopyTo(destination[KeyIdSize..HeaderSize]);
    }

    public static short ReadKeyId(ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length < KeyIdSize)
            throw new ArgumentException($"Ciphertext must be at least {KeyIdSize} bytes to read key id.", nameof(ciphertext));

        return BinaryPrimitives.ReadInt16BigEndian(ciphertext[..KeyIdSize]);
    }

    public static ReadOnlySpan<byte> ReadNonce(ReadOnlySpan<byte> ciphertext)
        => ciphertext.Slice(KeyIdSize, NonceSize);

    public static ReadOnlySpan<byte> ReadTag(ReadOnlySpan<byte> ciphertext)
        => ciphertext.Slice(HeaderSize, TagSize);

    public static ReadOnlySpan<byte> ReadBody(ReadOnlySpan<byte> ciphertext)
        => ciphertext[(HeaderSize + TagSize)..];
}
```

- [ ] **Step 4: Run CipherFormat tests — verify pass**

```
dotnet test test/Moongazing.OrionVault.Tests/Moongazing.OrionVault.Tests.csproj --filter FullyQualifiedName~CipherFormatTests
```
Expected: 3 tests PASS.

Note: `CipherFormat` is `internal`. Add `InternalsVisibleTo` to the core csproj so the tests can see it:
```xml
<!-- Append to src/Moongazing.OrionVault/Moongazing.OrionVault.csproj -->
<ItemGroup>
  <InternalsVisibleTo Include="Moongazing.OrionVault.Tests" />
  <InternalsVisibleTo Include="Moongazing.OrionVault.EntityFrameworkCore" />
  <InternalsVisibleTo Include="Moongazing.OrionVault.EntityFrameworkCore.Tests" />
  <InternalsVisibleTo Include="Moongazing.OrionVault.Testing" />
</ItemGroup>
```

- [ ] **Step 5: Write the failing test for AesGcmEncryptor round-trip**

`test/Moongazing.OrionVault.Tests/Internal/AesGcmEncryptorTests.cs`:
```csharp
namespace Moongazing.OrionVault.Tests.Internal;

using FluentAssertions;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Exceptions;
using Moongazing.OrionVault.Internal;
using Xunit;

public class AesGcmEncryptorTests
{
    private static readonly byte[] Key1 = new byte[32];   // all zeros, deterministic for tests
    private static readonly byte[] Key2 = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

    private sealed class FixedKeys : IKeyProvider
    {
        private readonly Dictionary<short, byte[]> _keys;
        public FixedKeys(short active, params (short id, byte[] key)[] keys)
        {
            ActiveKeyId = active;
            _keys = keys.ToDictionary(k => k.id, k => k.key);
        }
        public short ActiveKeyId { get; }
        public ReadOnlyMemory<byte>? TryGetKey(short keyId)
            => _keys.TryGetValue(keyId, out var k) ? k : null;
    }

    [Fact]
    public void EncryptString_then_DecryptString_round_trips()
    {
        var sut = new AesGcmEncryptor(new FixedKeys(1, (1, Key1)));

        var ciphertext = sut.EncryptString("hello world");
        var plaintext = sut.DecryptString(ciphertext);

        plaintext.Should().Be("hello world");
        ciphertext.Length.Should().Be(30 + System.Text.Encoding.UTF8.GetByteCount("hello world"));
        ciphertext[0].Should().Be(0);
        ciphertext[1].Should().Be(1);    // keyId = 1, big-endian
    }

    [Fact]
    public void EncryptString_with_empty_string_produces_30_byte_ciphertext()
    {
        var sut = new AesGcmEncryptor(new FixedKeys(1, (1, Key1)));

        var ciphertext = sut.EncryptString("");

        ciphertext.Length.Should().Be(30);
        sut.DecryptString(ciphertext).Should().Be("");
    }

    [Fact]
    public void EncryptBytes_round_trips_with_DecryptBytes()
    {
        var sut = new AesGcmEncryptor(new FixedKeys(1, (1, Key1)));
        var payload = new byte[] { 1, 2, 3, 4, 5 };

        var ciphertext = sut.EncryptBytes(payload);

        sut.DecryptBytes(ciphertext).Should().Equal(payload);
    }

    [Fact]
    public void Encrypt_uses_ActiveKeyId_for_new_writes()
    {
        var sut = new AesGcmEncryptor(new FixedKeys(active: 2, (1, Key1), (2, Key2)));

        var ciphertext = sut.EncryptString("x");

        CipherFormat.ReadKeyId(ciphertext).Should().Be(2);
    }

    [Fact]
    public void Decrypt_reads_old_key_for_legacy_ciphertext()
    {
        var sutOld = new AesGcmEncryptor(new FixedKeys(active: 1, (1, Key1)));
        var legacy = sutOld.EncryptString("oldvalue");

        var sutNew = new AesGcmEncryptor(new FixedKeys(active: 2, (1, Key1), (2, Key2)));

        sutNew.DecryptString(legacy).Should().Be("oldvalue");
    }

    [Fact]
    public void Decrypt_throws_on_tampering()
    {
        var sut = new AesGcmEncryptor(new FixedKeys(1, (1, Key1)));
        var ciphertext = sut.EncryptString("important");

        ciphertext[^1] ^= 0x01;   // flip one bit of the body

        var act = () => sut.DecryptString(ciphertext);
        act.Should().Throw<OrionVaultDecryptionException>();
    }

    [Fact]
    public void Decrypt_throws_OrionVaultKeyNotFoundException_for_unknown_key_id()
    {
        var encWithKey2 = new AesGcmEncryptor(new FixedKeys(active: 2, (2, Key2)));
        var ciphertext = encWithKey2.EncryptString("x");

        var encMissingKey2 = new AesGcmEncryptor(new FixedKeys(active: 1, (1, Key1)));

        var act = () => encMissingKey2.DecryptString(ciphertext);
        act.Should().Throw<OrionVaultKeyNotFoundException>()
            .Where(e => e.KeyId == 2);
    }

    [Fact]
    public void Decrypt_throws_on_too_short_ciphertext()
    {
        var sut = new AesGcmEncryptor(new FixedKeys(1, (1, Key1)));

        var act = () => sut.DecryptString(new byte[10]);
        act.Should().Throw<OrionVaultDecryptionException>();
    }

    [Fact]
    public void EncryptString_uses_fresh_random_nonce_each_call()
    {
        var sut = new AesGcmEncryptor(new FixedKeys(1, (1, Key1)));

        var a = sut.EncryptString("same");
        var b = sut.EncryptString("same");

        a.Should().NotEqual(b);   // nonces differ ⇒ ciphertexts differ
    }
}
```

- [ ] **Step 6: Run test to verify it fails**

```
dotnet test test/Moongazing.OrionVault.Tests/Moongazing.OrionVault.Tests.csproj --filter FullyQualifiedName~AesGcmEncryptorTests
```
Expected: FAIL — `AesGcmEncryptor` not defined.

- [ ] **Step 7: Implement AesGcmEncryptor**

`src/Moongazing.OrionVault/Internal/AesGcmEncryptor.cs`:
```csharp
namespace Moongazing.OrionVault.Internal;

using System.Security.Cryptography;
using System.Text;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Exceptions;

internal sealed class AesGcmEncryptor : IEncryptor
{
    private const int KeyLengthBytes = 32;
    private readonly IKeyProvider _keys;

    public AesGcmEncryptor(IKeyProvider keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        _keys = keys;
    }

    public byte[] EncryptString(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        return EncryptInternal(bytes);
    }

    public string DecryptString(byte[] ciphertext)
    {
        var plain = DecryptInternal(ciphertext);
        return Encoding.UTF8.GetString(plain);
    }

    public byte[] EncryptBytes(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return EncryptInternal(plaintext);
    }

    public byte[] DecryptBytes(byte[] ciphertext) => DecryptInternal(ciphertext);

    private byte[] EncryptInternal(ReadOnlySpan<byte> plaintext)
    {
        var keyId = _keys.ActiveKeyId;
        var key = _keys.TryGetKey(keyId)
            ?? throw new OrionVaultConfigurationException(
                $"Active key id {keyId} is not registered in the IKeyProvider.");
        if (key.Length != KeyLengthBytes)
            throw new OrionVaultConfigurationException(
                $"Key {keyId} is {key.Length} bytes; expected {KeyLengthBytes}.");

        var output = new byte[CipherFormat.HeaderSize + CipherFormat.TagSize + plaintext.Length];
        var nonce = output.AsSpan(CipherFormat.KeyIdSize, CipherFormat.NonceSize);
        RandomNumberGenerator.Fill(nonce);

        CipherFormat.WriteHeader(output, keyId, nonce);
        var tag = output.AsSpan(CipherFormat.HeaderSize, CipherFormat.TagSize);
        var body = output.AsSpan(CipherFormat.HeaderSize + CipherFormat.TagSize);

        using var aes = new AesGcm(key.Span, CipherFormat.TagSize);
        aes.Encrypt(nonce, plaintext, body, tag);
        return output;
    }

    private byte[] DecryptInternal(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        if (ciphertext.Length < CipherFormat.MinimumCiphertextLength)
            throw new OrionVaultDecryptionException(
                $"Ciphertext length {ciphertext.Length} is below the minimum {CipherFormat.MinimumCiphertextLength}.");

        var keyId = CipherFormat.ReadKeyId(ciphertext);
        var key = _keys.TryGetKey(keyId)
            ?? throw new OrionVaultKeyNotFoundException(keyId);

        var nonce = CipherFormat.ReadNonce(ciphertext);
        var tag = CipherFormat.ReadTag(ciphertext);
        var body = CipherFormat.ReadBody(ciphertext);
        var plaintext = new byte[body.Length];

        try
        {
            using var aes = new AesGcm(key.Span, CipherFormat.TagSize);
            aes.Decrypt(nonce, body, tag, plaintext);
            return plaintext;
        }
        catch (CryptographicException ex)
        {
            throw new OrionVaultDecryptionException(
                "Ciphertext failed authentication (tampered, wrong key, or corrupted).", ex);
        }
    }
}
```

- [ ] **Step 8: Run all tests — verify pass**

```
dotnet test test/Moongazing.OrionVault.Tests/Moongazing.OrionVault.Tests.csproj
```
Expected: 12 tests PASS (3 exception + 3 cipher format + 9 encryptor).

- [ ] **Step 9: Commit**

```
git add src/Moongazing.OrionVault/ test/Moongazing.OrionVault.Tests/
git commit -m "feat: AES-256-GCM encryptor with [keyId|nonce|tag|ciphertext] format"
git push
```

---

## Task 3: Options + StaticKeyProvider + DI registration

**Files:**
- Create: `src/Moongazing.OrionVault/Options/OrionVaultOptions.cs`
- Create: `src/Moongazing.OrionVault/Options/StaticKeysBuilder.cs`
- Create: `src/Moongazing.OrionVault/Internal/StaticKeyProvider.cs`
- Create: `src/Moongazing.OrionVault/DependencyInjection/OrionVaultBuilder.cs`
- Create: `src/Moongazing.OrionVault/DependencyInjection/OrionVaultServiceCollectionExtensions.cs`
- Test: `test/Moongazing.OrionVault.Tests/DependencyInjection/AddOrionVaultTests.cs`

- [ ] **Step 1: Write the failing test for AddOrionVault round-trip**

`test/Moongazing.OrionVault.Tests/DependencyInjection/AddOrionVaultTests.cs`:
```csharp
namespace Moongazing.OrionVault.Tests.DependencyInjection;

using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Exceptions;
using Xunit;

public class AddOrionVaultTests
{
    private const string Key32B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    [Fact]
    public void AddOrionVault_registers_singletons_and_round_trips_a_value()
    {
        var sp = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(keyId: 1, base64Key: Key32B64));
                o.ActiveKeyId = 1;
            })
            .Services
            .BuildServiceProvider();

        var encryptor = sp.GetRequiredService<IEncryptor>();
        var keys = sp.GetRequiredService<IKeyProvider>();

        keys.ActiveKeyId.Should().Be(1);
        var ct = encryptor.EncryptString("hello");
        encryptor.DecryptString(ct).Should().Be("hello");
    }

    [Fact]
    public void AddOrionVault_throws_if_ActiveKeyId_not_registered()
    {
        var act = () => new ServiceCollection().AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(keyId: 1, base64Key: Key32B64));
            o.ActiveKeyId = 99;
        });

        act.Should().Throw<OrionVaultConfigurationException>()
            .WithMessage("*99*");
    }

    [Fact]
    public void AddOrionVault_throws_if_no_keys_registered()
    {
        var act = () => new ServiceCollection().AddOrionVault(o =>
        {
            o.ActiveKeyId = 1;
        });

        act.Should().Throw<OrionVaultConfigurationException>()
            .WithMessage("*at least one key*");
    }

    [Fact]
    public void StaticKeys_Add_throws_on_duplicate_key_id()
    {
        var act = () => new ServiceCollection().AddOrionVault(o =>
        {
            o.UseStaticKeys(k =>
            {
                k.Add(keyId: 1, base64Key: Key32B64);
                k.Add(keyId: 1, base64Key: Key32B64);
            });
            o.ActiveKeyId = 1;
        });

        act.Should().Throw<OrionVaultConfigurationException>()
            .WithMessage("*duplicate*1*");
    }

    [Fact]
    public void StaticKeys_Add_throws_on_non_32_byte_key()
    {
        const string shortKey = "AAAAAAAAAA==";   // 6 bytes
        var act = () => new ServiceCollection().AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(keyId: 1, base64Key: shortKey));
            o.ActiveKeyId = 1;
        });

        act.Should().Throw<OrionVaultConfigurationException>()
            .WithMessage("*32 bytes*");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```
dotnet test test/Moongazing.OrionVault.Tests/Moongazing.OrionVault.Tests.csproj --filter FullyQualifiedName~AddOrionVaultTests
```
Expected: FAIL — `AddOrionVault` not defined.

- [ ] **Step 3: Implement options + builder + provider**

`src/Moongazing.OrionVault/Options/StaticKeysBuilder.cs`:
```csharp
namespace Moongazing.OrionVault.Options;

using Moongazing.OrionVault.Exceptions;

public sealed class StaticKeysBuilder
{
    private readonly Dictionary<short, byte[]> _keys = new();

    public StaticKeysBuilder Add(short keyId, string base64Key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(base64Key);
        if (_keys.ContainsKey(keyId))
            throw new OrionVaultConfigurationException(
                $"Duplicate key id {keyId} in StaticKeysBuilder.");

        byte[] bytes;
        try { bytes = Convert.FromBase64String(base64Key); }
        catch (FormatException ex)
        {
            throw new OrionVaultConfigurationException(
                $"Key {keyId} is not valid base64.", ex);
        }

        if (bytes.Length != 32)
            throw new OrionVaultConfigurationException(
                $"Key {keyId} decoded to {bytes.Length} bytes; expected 32 bytes (256-bit AES key).");

        _keys[keyId] = bytes;
        return this;
    }

    internal IReadOnlyDictionary<short, byte[]> Build() => _keys;
}
```

`src/Moongazing.OrionVault/Options/OrionVaultOptions.cs`:
```csharp
namespace Moongazing.OrionVault.Options;

public sealed class OrionVaultOptions
{
    private StaticKeysBuilder? _keys;

    public short ActiveKeyId { get; set; }

    public void UseStaticKeys(Action<StaticKeysBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        _keys ??= new StaticKeysBuilder();
        configure(_keys);
    }

    internal StaticKeysBuilder? KeysBuilder => _keys;
}
```

`src/Moongazing.OrionVault/Internal/StaticKeyProvider.cs`:
```csharp
namespace Moongazing.OrionVault.Internal;

using Moongazing.OrionVault.Abstractions;

internal sealed class StaticKeyProvider : IKeyProvider
{
    private readonly IReadOnlyDictionary<short, byte[]> _keys;

    public StaticKeyProvider(IReadOnlyDictionary<short, byte[]> keys, short activeKeyId)
    {
        _keys = keys;
        ActiveKeyId = activeKeyId;
    }

    public short ActiveKeyId { get; }

    public ReadOnlyMemory<byte>? TryGetKey(short keyId)
        => _keys.TryGetValue(keyId, out var k) ? k : null;
}
```

`src/Moongazing.OrionVault/DependencyInjection/OrionVaultBuilder.cs`:
```csharp
namespace Moongazing.OrionVault.DependencyInjection;

using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Returned from <see cref="OrionVaultServiceCollectionExtensions.AddOrionVault"/>.
/// Acts as a typed handle for chained registration extensions (UseEntityFrameworkCore,
/// UseTestKeys, etc.).
/// </summary>
public sealed class OrionVaultBuilder
{
    public OrionVaultBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    public IServiceCollection Services { get; }
}
```

`src/Moongazing.OrionVault/DependencyInjection/OrionVaultServiceCollectionExtensions.cs`:
```csharp
namespace Moongazing.OrionVault.DependencyInjection;

using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Exceptions;
using Moongazing.OrionVault.Internal;
using Moongazing.OrionVault.Options;

public static class OrionVaultServiceCollectionExtensions
{
    public static OrionVaultBuilder AddOrionVault(
        this IServiceCollection services,
        Action<OrionVaultOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new OrionVaultOptions();
        configure(options);

        var builder = options.KeysBuilder
            ?? throw new OrionVaultConfigurationException(
                "OrionVault requires at least one key. Call options.UseStaticKeys(...).");

        var keys = builder.Build();
        if (keys.Count == 0)
            throw new OrionVaultConfigurationException(
                "OrionVault requires at least one key. Call StaticKeysBuilder.Add(...).");
        if (!keys.ContainsKey(options.ActiveKeyId))
            throw new OrionVaultConfigurationException(
                $"ActiveKeyId {options.ActiveKeyId} is not registered. Registered ids: [{string.Join(", ", keys.Keys)}].");

        services.AddSingleton<IKeyProvider>(_ => new StaticKeyProvider(keys, options.ActiveKeyId));
        services.AddSingleton<IEncryptor, AesGcmEncryptor>();

        return new OrionVaultBuilder(services);
    }
}
```

- [ ] **Step 4: Run tests — verify pass**

```
dotnet test test/Moongazing.OrionVault.Tests/Moongazing.OrionVault.Tests.csproj
```
Expected: all tests PASS (12 from Tasks 1-2 + 5 new = 17).

- [ ] **Step 5: Commit**

```
git add src/Moongazing.OrionVault/ test/Moongazing.OrionVault.Tests/
git commit -m "feat: AddOrionVault DI registration with StaticKeyProvider and config validation"
git push
```

---

## Task 4: Telemetry (ActivitySource + Meter + counters + histogram)

**Files:**
- Create: `src/Moongazing.OrionVault/Diagnostics/OrionVaultDiagnostics.cs`
- Modify: `src/Moongazing.OrionVault/Internal/AesGcmEncryptor.cs` (wire telemetry into Encrypt/Decrypt)
- Modify: `src/Moongazing.OrionVault/DependencyInjection/OrionVaultServiceCollectionExtensions.cs` (register diagnostics singleton)
- Test: `test/Moongazing.OrionVault.Tests/Diagnostics/OrionVaultDiagnosticsTests.cs`

- [ ] **Step 1: Write the failing test for telemetry counters**

`test/Moongazing.OrionVault.Tests/Diagnostics/OrionVaultDiagnosticsTests.cs`:
```csharp
namespace Moongazing.OrionVault.Tests.Diagnostics;

using System.Diagnostics.Metrics;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.DependencyInjection;
using Xunit;

public class OrionVaultDiagnosticsTests
{
    private const string Key32B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    [Fact]
    public void Encrypt_increments_encryptions_counter()
    {
        long encryptions = 0;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (inst, l) =>
        {
            if (inst.Meter.Name == OrionVaultDiagnostics.MeterName &&
                inst.Name == "orionvault.encryptions")
                l.EnableMeasurementEvents(inst);
        };
        listener.SetMeasurementEventCallback<long>((_, val, _, _) => Interlocked.Add(ref encryptions, val));
        listener.Start();

        var sp = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(1, Key32B64));
                o.ActiveKeyId = 1;
            })
            .Services
            .BuildServiceProvider();
        var enc = sp.GetRequiredService<IEncryptor>();
        enc.EncryptString("a");
        enc.EncryptString("b");

        listener.RecordObservableInstruments();
        Volatile.Read(ref encryptions).Should().BeGreaterOrEqualTo(2);
    }

    [Fact]
    public void Decrypt_failure_increments_failures_counter_with_reason_tag()
    {
        var reasons = new List<string>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (inst, l) =>
        {
            if (inst.Meter.Name == OrionVaultDiagnostics.MeterName &&
                inst.Name == "orionvault.decryption.failures")
                l.EnableMeasurementEvents(inst);
        };
        listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            foreach (var t in tags)
                if (t.Key == "reason" && t.Value is string r) reasons.Add(r);
        });
        listener.Start();

        var sp = new ServiceCollection()
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(1, Key32B64));
                o.ActiveKeyId = 1;
            })
            .Services
            .BuildServiceProvider();
        var enc = sp.GetRequiredService<IEncryptor>();
        var ct = enc.EncryptString("x");
        ct[^1] ^= 0xFF;
        try { enc.DecryptString(ct); } catch { }

        reasons.Should().Contain("tampered");
    }

    [Fact]
    public void Diagnostics_singleton_is_registered()
    {
        var sp = new ServiceCollection()
            .AddOrionVault(o => { o.UseStaticKeys(k => k.Add(1, Key32B64)); o.ActiveKeyId = 1; })
            .Services
            .BuildServiceProvider();

        sp.GetRequiredService<OrionVaultDiagnostics>().Should().NotBeNull();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```
dotnet test test/Moongazing.OrionVault.Tests/Moongazing.OrionVault.Tests.csproj --filter FullyQualifiedName~OrionVaultDiagnosticsTests
```
Expected: FAIL — `OrionVaultDiagnostics` not defined.

- [ ] **Step 3: Implement OrionVaultDiagnostics**

`src/Moongazing.OrionVault/Diagnostics/OrionVaultDiagnostics.cs`:
```csharp
namespace Moongazing.OrionVault.Diagnostics;

using System.Diagnostics;
using System.Diagnostics.Metrics;

public sealed class OrionVaultDiagnostics : IDisposable
{
    public const string MeterName = "Moongazing.OrionVault";
    public const string ActivitySourceName = "Moongazing.OrionVault";

    public ActivitySource ActivitySource { get; }
    public Meter Meter { get; }

    internal Counter<long> Encryptions { get; }
    internal Counter<long> Decryptions { get; }
    internal Counter<long> DecryptionFailures { get; }
    internal Counter<long> KeyLookups { get; }
    internal Counter<long> KeyNotFound { get; }
    internal Histogram<double> Duration { get; }

    public OrionVaultDiagnostics()
    {
        ActivitySource = new ActivitySource(ActivitySourceName, "0.1.0");
        Meter = new Meter(MeterName, "0.1.0");
        Encryptions = Meter.CreateCounter<long>("orionvault.encryptions", "{operations}",
            "Number of encryption operations performed.");
        Decryptions = Meter.CreateCounter<long>("orionvault.decryptions", "{operations}",
            "Number of decryption operations performed.");
        DecryptionFailures = Meter.CreateCounter<long>("orionvault.decryption.failures", "{operations}",
            "Number of failed decryptions, tagged by reason.");
        KeyLookups = Meter.CreateCounter<long>("orionvault.key_lookups", "{operations}",
            "Number of key lookups performed against the IKeyProvider.");
        KeyNotFound = Meter.CreateCounter<long>("orionvault.key_not_found", "{operations}",
            "Number of times the IKeyProvider returned null for a key id.");
        Duration = Meter.CreateHistogram<double>("orionvault.encryption.duration_ms", "ms",
            "Duration of encrypt/decrypt operations.");
    }

    public void Dispose()
    {
        ActivitySource.Dispose();
        Meter.Dispose();
    }
}
```

- [ ] **Step 4: Wire diagnostics into AesGcmEncryptor**

Modify `src/Moongazing.OrionVault/Internal/AesGcmEncryptor.cs` constructor and methods:

```csharp
namespace Moongazing.OrionVault.Internal;

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

    public AesGcmEncryptor(IKeyProvider keys, OrionVaultDiagnostics diag)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(diag);
        _keys = keys;
        _diag = diag;
    }

    public byte[] EncryptString(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return EncryptInternal(Encoding.UTF8.GetBytes(plaintext));
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
            return output;
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
                activity?.SetTag("outcome", "tampered");
                throw new OrionVaultDecryptionException(
                    "Ciphertext failed authentication (tampered, wrong key, or corrupted).", ex);
            }

            _diag.Decryptions.Add(1,
                new KeyValuePair<string, object?>("algorithm", "aes-gcm-256"),
                new KeyValuePair<string, object?>("key_id", keyId));
            activity?.SetTag("outcome", "success");
            return plaintext;
        }
        catch (OrionVaultKeyNotFoundException)
        {
            _diag.DecryptionFailures.Add(1,
                new KeyValuePair<string, object?>("reason", "key_not_found"),
                new KeyValuePair<string, object?>("key_id", keyId));
            activity?.SetTag("outcome", "key_not_found");
            throw;
        }
        finally
        {
            _diag.Duration.Record(Stopwatch.GetElapsedTime(sw).TotalMilliseconds,
                new KeyValuePair<string, object?>("algorithm", "aes-gcm-256"),
                new KeyValuePair<string, object?>("operation", "decrypt"));
        }
    }

    private ReadOnlyMemory<byte> LookupKey(short keyId)
    {
        var k = _keys.TryGetKey(keyId);
        _diag.KeyLookups.Add(1,
            new KeyValuePair<string, object?>("key_id", keyId),
            new KeyValuePair<string, object?>("outcome", k.HasValue ? "hit" : "miss"));
        if (k is null)
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
```

- [ ] **Step 5: Register OrionVaultDiagnostics as singleton**

Modify `src/Moongazing.OrionVault/DependencyInjection/OrionVaultServiceCollectionExtensions.cs`. Inside `AddOrionVault`, BEFORE `services.AddSingleton<IEncryptor, AesGcmEncryptor>()`:

```csharp
services.AddSingleton<OrionVaultDiagnostics>();
```

Add `using Moongazing.OrionVault.Diagnostics;` to the top.

- [ ] **Step 6: Update FixedKeys test fixture to use diagnostics**

The existing `AesGcmEncryptorTests.cs` constructs `new AesGcmEncryptor(new FixedKeys(...))` — now requires a second arg. Update each `new AesGcmEncryptor(...)` to:

```csharp
new AesGcmEncryptor(new FixedKeys(...), new OrionVaultDiagnostics())
```

Add `using Moongazing.OrionVault.Diagnostics;` to that file.

- [ ] **Step 7: Run all tests — verify pass**

```
dotnet test test/Moongazing.OrionVault.Tests/Moongazing.OrionVault.Tests.csproj
```
Expected: all tests PASS (17 from Tasks 1-3 + 3 new = 20).

- [ ] **Step 8: Commit**

```
git add src/Moongazing.OrionVault/ test/Moongazing.OrionVault.Tests/
git commit -m "feat: telemetry — ActivitySource, 5 counters, 1 histogram via OrionVaultDiagnostics"
git push
```

---

## Task 5: EF Core value converters + [Encrypted] attribute

**Files:**
- Create: `src/Moongazing.OrionVault.EntityFrameworkCore/EncryptedAttribute.cs`
- Create: `src/Moongazing.OrionVault.EntityFrameworkCore/Internal/EncryptedStringConverter.cs`
- Create: `src/Moongazing.OrionVault.EntityFrameworkCore/Internal/EncryptedBytesConverter.cs`
- Create: `src/Moongazing.OrionVault.EntityFrameworkCore/Internal/EncryptedValueConverterFactory.cs`
- Test: `test/Moongazing.OrionVault.EntityFrameworkCore.Tests/Internal/EncryptedConverterTests.cs`

- [ ] **Step 1: Write the failing test for value converters**

`test/Moongazing.OrionVault.EntityFrameworkCore.Tests/Internal/EncryptedConverterTests.cs`:
```csharp
namespace Moongazing.OrionVault.EntityFrameworkCore.Tests.Internal;

using FluentAssertions;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.EntityFrameworkCore.Internal;
using Moongazing.OrionVault.Internal;
using Xunit;

public class EncryptedConverterTests
{
    private static readonly byte[] Key = new byte[32];

    private sealed class OneKey : IKeyProvider
    {
        public short ActiveKeyId => 1;
        public ReadOnlyMemory<byte>? TryGetKey(short keyId) => keyId == 1 ? Key : null;
    }

    [Fact]
    public void EncryptedStringConverter_round_trips_via_EF_value_converter_API()
    {
        var encryptor = new AesGcmEncryptor(new OneKey(), new OrionVaultDiagnostics());
        var sut = new EncryptedStringConverter(encryptor);

        var modelValue = "hello";
        var providerValue = (byte[])sut.ConvertToProvider(modelValue)!;
        var back = (string)sut.ConvertFromProvider(providerValue)!;

        back.Should().Be("hello");
    }

    [Fact]
    public void EncryptedBytesConverter_round_trips_via_EF_value_converter_API()
    {
        var encryptor = new AesGcmEncryptor(new OneKey(), new OrionVaultDiagnostics());
        var sut = new EncryptedBytesConverter(encryptor);

        var modelValue = new byte[] { 1, 2, 3 };
        var providerValue = (byte[])sut.ConvertToProvider(modelValue)!;
        var back = (byte[])sut.ConvertFromProvider(providerValue)!;

        back.Should().Equal(modelValue);
    }

    [Fact]
    public void Factory_returns_string_converter_for_string_clr_type()
    {
        var encryptor = new AesGcmEncryptor(new OneKey(), new OrionVaultDiagnostics());
        var factory = new EncryptedValueConverterFactory(encryptor);

        var converter = factory.For(typeof(string));
        converter.Should().BeOfType<EncryptedStringConverter>();
    }

    [Fact]
    public void Factory_returns_bytes_converter_for_byte_array_clr_type()
    {
        var encryptor = new AesGcmEncryptor(new OneKey(), new OrionVaultDiagnostics());
        var factory = new EncryptedValueConverterFactory(encryptor);

        var converter = factory.For(typeof(byte[]));
        converter.Should().BeOfType<EncryptedBytesConverter>();
    }

    [Fact]
    public void Factory_throws_for_unsupported_type()
    {
        var encryptor = new AesGcmEncryptor(new OneKey(), new OrionVaultDiagnostics());
        var factory = new EncryptedValueConverterFactory(encryptor);

        var act = () => factory.For(typeof(int));
        act.Should().Throw<Moongazing.OrionVault.Exceptions.OrionVaultConfigurationException>()
            .WithMessage("*int*");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```
dotnet test test/Moongazing.OrionVault.EntityFrameworkCore.Tests/Moongazing.OrionVault.EntityFrameworkCore.Tests.csproj
```
Expected: FAIL — types not defined.

- [ ] **Step 3: Implement [Encrypted] attribute and converters**

`src/Moongazing.OrionVault.EntityFrameworkCore/EncryptedAttribute.cs`:
```csharp
namespace Moongazing.OrionVault.EntityFrameworkCore;

/// <summary>
/// Marks a property for transparent at-rest encryption. Supported CLR types
/// are <see cref="string"/> and <c>byte[]</c>. Other types produce analyzer
/// error <c>OV0001</c> at compile time.
/// </summary>
[AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
public sealed class EncryptedAttribute : Attribute { }
```

`src/Moongazing.OrionVault.EntityFrameworkCore/Internal/EncryptedStringConverter.cs`:
```csharp
namespace Moongazing.OrionVault.EntityFrameworkCore.Internal;

using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Moongazing.OrionVault.Abstractions;

internal sealed class EncryptedStringConverter : ValueConverter<string, byte[]>
{
    public EncryptedStringConverter(IEncryptor encryptor)
        : base(
            v => encryptor.EncryptString(v),
            v => encryptor.DecryptString(v))
    { }
}
```

`src/Moongazing.OrionVault.EntityFrameworkCore/Internal/EncryptedBytesConverter.cs`:
```csharp
namespace Moongazing.OrionVault.EntityFrameworkCore.Internal;

using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Moongazing.OrionVault.Abstractions;

internal sealed class EncryptedBytesConverter : ValueConverter<byte[], byte[]>
{
    public EncryptedBytesConverter(IEncryptor encryptor)
        : base(
            v => encryptor.EncryptBytes(v),
            v => encryptor.DecryptBytes(v))
    { }
}
```

`src/Moongazing.OrionVault.EntityFrameworkCore/Internal/EncryptedValueConverterFactory.cs`:
```csharp
namespace Moongazing.OrionVault.EntityFrameworkCore.Internal;

using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Exceptions;

internal sealed class EncryptedValueConverterFactory
{
    private readonly EncryptedStringConverter _stringConverter;
    private readonly EncryptedBytesConverter _bytesConverter;

    public EncryptedValueConverterFactory(IEncryptor encryptor)
    {
        ArgumentNullException.ThrowIfNull(encryptor);
        _stringConverter = new EncryptedStringConverter(encryptor);
        _bytesConverter = new EncryptedBytesConverter(encryptor);
    }

    public ValueConverter For(Type clrType)
    {
        if (clrType == typeof(string)) return _stringConverter;
        if (clrType == typeof(byte[])) return _bytesConverter;
        throw new OrionVaultConfigurationException(
            $"OrionVault does not support encrypted property type '{clrType}'. " +
            "Supported types are string and byte[].");
    }
}
```

Add `InternalsVisibleTo` for the test project to the EF Core csproj:
```xml
<!-- src/Moongazing.OrionVault.EntityFrameworkCore/Moongazing.OrionVault.EntityFrameworkCore.csproj -->
<ItemGroup>
  <InternalsVisibleTo Include="Moongazing.OrionVault.EntityFrameworkCore.Tests" />
</ItemGroup>
```

- [ ] **Step 4: Run tests — verify pass**

```
dotnet test test/Moongazing.OrionVault.EntityFrameworkCore.Tests/Moongazing.OrionVault.EntityFrameworkCore.Tests.csproj
```
Expected: 5 tests PASS.

- [ ] **Step 5: Commit**

```
git add src/Moongazing.OrionVault.EntityFrameworkCore/ test/Moongazing.OrionVault.EntityFrameworkCore.Tests/
git commit -m "feat: EF Core value converters and [Encrypted] attribute"
git push
```

---

## Task 6: EF Core model integration (fluent + configurator + customizer)

**Files:**
- Create: `src/Moongazing.OrionVault.EntityFrameworkCore/PropertyBuilderExtensions.cs`
- Create: `src/Moongazing.OrionVault.EntityFrameworkCore/Internal/EncryptionConfigurator.cs`
- Create: `src/Moongazing.OrionVault.EntityFrameworkCore/Internal/OrionVaultModelCustomizer.cs`
- Test: `test/Moongazing.OrionVault.EntityFrameworkCore.Tests/ModelIntegrationTests.cs`

- [ ] **Step 1: Write the failing test — attribute and fluent both attach converter**

`test/Moongazing.OrionVault.EntityFrameworkCore.Tests/ModelIntegrationTests.cs`:
```csharp
namespace Moongazing.OrionVault.EntityFrameworkCore.Tests;

using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.EntityFrameworkCore.Internal;
using Moongazing.OrionVault.Exceptions;
using Moongazing.OrionVault.Internal;
using Xunit;

public class ModelIntegrationTests
{
    private static readonly byte[] Key = new byte[32];

    private sealed class OneKey : IKeyProvider
    {
        public short ActiveKeyId => 1;
        public ReadOnlyMemory<byte>? TryGetKey(short keyId) => keyId == 1 ? Key : null;
    }

    public class UserAttr
    {
        public Guid Id { get; set; }
        [Encrypted] public string Email { get; set; } = null!;
    }

    public class UserFluent
    {
        public Guid Id { get; set; }
        public string Email { get; set; } = null!;
    }

    public class UserBadType
    {
        public Guid Id { get; set; }
        [Encrypted] public int Number { get; set; }
    }

    private sealed class AttrCtx : DbContext
    {
        public AttrCtx(DbContextOptions opt) : base(opt) { }
        public DbSet<UserAttr> Users => Set<UserAttr>();
    }

    private sealed class FluentCtx : DbContext
    {
        public FluentCtx(DbContextOptions opt) : base(opt) { }
        public DbSet<UserFluent> Users => Set<UserFluent>();
        protected override void OnModelCreating(ModelBuilder mb)
            => mb.Entity<UserFluent>().Property(u => u.Email).IsEncrypted();
    }

    private sealed class BadTypeCtx : DbContext
    {
        public BadTypeCtx(DbContextOptions opt) : base(opt) { }
        public DbSet<UserBadType> Users => Set<UserBadType>();
    }

    private static EncryptionConfigurator CreateConfigurator()
    {
        var enc = new AesGcmEncryptor(new OneKey(), new OrionVaultDiagnostics());
        return new EncryptionConfigurator(new EncryptedValueConverterFactory(enc));
    }

    [Fact]
    public void Attribute_marks_property_for_encryption()
    {
        var opts = new DbContextOptionsBuilder<AttrCtx>().UseSqlite("Data Source=:memory:").Options;
        using var ctx = new AttrCtx(opts);
        var model = ctx.Model;
        CreateConfigurator().Configure(new ModelBuilder(model.GetRelationalModel().Model.RemoveAnnotation /* placeholder */));
        // For this test we use a simpler API: just verify the configurator sees it.
        // (The full wiring is tested via OrionVaultModelCustomizer in step 5.)
        var prop = model.FindEntityType(typeof(UserAttr))!.FindProperty(nameof(UserAttr.Email))!;
        prop.GetCustomAttributes(false).Should().Contain(a => a is EncryptedAttribute);
    }

    [Fact]
    public void IsEncrypted_sets_annotation_on_property()
    {
        var opts = new DbContextOptionsBuilder<FluentCtx>().UseSqlite("Data Source=:memory:").Options;
        using var ctx = new FluentCtx(opts);

        var prop = ctx.Model.FindEntityType(typeof(UserFluent))!.FindProperty(nameof(UserFluent.Email))!;
        prop.FindAnnotation("OrionVault:Encrypted")?.Value.Should().Be(true);
    }

    [Fact]
    public void Configurator_throws_when_attribute_on_unsupported_type()
    {
        var opts = new DbContextOptionsBuilder<BadTypeCtx>().UseSqlite("Data Source=:memory:").Options;
        using var ctx = new BadTypeCtx(opts);
        var mb = new ModelBuilder();
        mb.Entity<UserBadType>();
        var act = () => CreateConfigurator().Configure(mb);
        act.Should().Throw<OrionVaultConfigurationException>()
            .WithMessage("*Number*");
    }
}
```

(Note: the first test's `ModelBuilder` construction is illustrative — the real wiring path is via `OrionVaultModelCustomizer` which the test in Task 7 exercises end-to-end. For Step 1's failing test, simplify to focus on the **annotation** and **exception** assertions; the attribute-detection-and-converter-attach flow is fully validated in Task 7's integration test.)

Simplified version for Step 1 — replace the first test with:

```csharp
[Fact]
public void Configurator_attaches_string_converter_for_attribute_marked_property()
{
    var mb = new ModelBuilder();
    mb.Entity<UserAttr>();
    CreateConfigurator().Configure(mb);

    var prop = mb.Model.FindEntityType(typeof(UserAttr))!.FindProperty(nameof(UserAttr.Email))!;
    prop.GetValueConverter().Should().BeOfType<EncryptedStringConverter>();
}
```

- [ ] **Step 2: Run test to verify it fails**

```
dotnet test test/Moongazing.OrionVault.EntityFrameworkCore.Tests/Moongazing.OrionVault.EntityFrameworkCore.Tests.csproj --filter FullyQualifiedName~ModelIntegrationTests
```
Expected: FAIL.

- [ ] **Step 3: Implement PropertyBuilderExtensions (fluent IsEncrypted)**

`src/Moongazing.OrionVault.EntityFrameworkCore/PropertyBuilderExtensions.cs`:
```csharp
namespace Moongazing.OrionVault.EntityFrameworkCore;

using Microsoft.EntityFrameworkCore.Metadata.Builders;

public static class PropertyBuilderExtensions
{
    internal const string EncryptedAnnotation = "OrionVault:Encrypted";

    public static PropertyBuilder<string> IsEncrypted(this PropertyBuilder<string> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.HasAnnotation(EncryptedAnnotation, true);
        return builder;
    }

    public static PropertyBuilder<byte[]> IsEncrypted(this PropertyBuilder<byte[]> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.HasAnnotation(EncryptedAnnotation, true);
        return builder;
    }
}
```

- [ ] **Step 4: Implement EncryptionConfigurator**

`src/Moongazing.OrionVault.EntityFrameworkCore/Internal/EncryptionConfigurator.cs`:
```csharp
namespace Moongazing.OrionVault.EntityFrameworkCore.Internal;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Exceptions;

internal sealed class EncryptionConfigurator : IEncryptionConfigurator
{
    private readonly EncryptedValueConverterFactory _factory;

    public EncryptionConfigurator(EncryptedValueConverterFactory factory)
    {
        ArgumentNullException.ThrowIfNull(factory);
        _factory = factory;
    }

    public void Configure(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        foreach (var prop in entityType.GetProperties())
        {
            if (!ShouldEncrypt(prop)) continue;

            if (prop.ClrType != typeof(string) && prop.ClrType != typeof(byte[]))
                throw new OrionVaultConfigurationException(
                    $"Property '{entityType.ClrType.Name}.{prop.Name}' has type '{prop.ClrType}' which OrionVault does not support. " +
                    "Supported types: string, byte[].");

            prop.SetValueConverter(_factory.For(prop.ClrType));
        }
    }

    private static bool ShouldEncrypt(IMutableProperty prop)
    {
        if (prop.FindAnnotation(PropertyBuilderExtensions.EncryptedAnnotation)?.Value is true)
            return true;

        var clrProp = prop.PropertyInfo;
        if (clrProp is not null && clrProp.GetCustomAttributes(typeof(EncryptedAttribute), inherit: true).Length > 0)
            return true;

        return false;
    }
}
```

- [ ] **Step 5: Implement OrionVaultModelCustomizer**

`src/Moongazing.OrionVault.EntityFrameworkCore/Internal/OrionVaultModelCustomizer.cs`:
```csharp
namespace Moongazing.OrionVault.EntityFrameworkCore.Internal;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Moongazing.OrionVault.Abstractions;

internal sealed class OrionVaultModelCustomizer : IModelCustomizer
{
    private readonly IModelCustomizer _inner;
    private readonly IEncryptionConfigurator _configurator;

    public OrionVaultModelCustomizer(IModelCustomizer inner, IEncryptionConfigurator configurator)
    {
        _inner = inner;
        _configurator = configurator;
    }

    public void Customize(ModelBuilder modelBuilder, DbContext context)
    {
        _inner.Customize(modelBuilder, context);
        _configurator.Configure(modelBuilder);
    }
}
```

- [ ] **Step 6: Run tests — verify pass**

```
dotnet test test/Moongazing.OrionVault.EntityFrameworkCore.Tests/Moongazing.OrionVault.EntityFrameworkCore.Tests.csproj
```
Expected: 3 ModelIntegrationTests + 5 EncryptedConverterTests PASS.

- [ ] **Step 7: Commit**

```
git add src/Moongazing.OrionVault.EntityFrameworkCore/ test/Moongazing.OrionVault.EntityFrameworkCore.Tests/
git commit -m "feat: EF Core model integration — IsEncrypted() fluent, EncryptionConfigurator, OrionVaultModelCustomizer"
git push
```

---

## Task 7: EF Core DI wiring — UseEntityFrameworkCore + UseOrionVault

**Files:**
- Create: `src/Moongazing.OrionVault.EntityFrameworkCore/DependencyInjection/OrionVaultEntityFrameworkCoreBuilderExtensions.cs`
- Test: `test/Moongazing.OrionVault.EntityFrameworkCore.Tests/EndToEndEncryptionTests.cs`

- [ ] **Step 1: Write the failing end-to-end SQLite test**

`test/Moongazing.OrionVault.EntityFrameworkCore.Tests/EndToEndEncryptionTests.cs`:
```csharp
namespace Moongazing.OrionVault.EntityFrameworkCore.Tests;

using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;
using Xunit;

public class EndToEndEncryptionTests : IDisposable
{
    private const string Key32B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    private readonly SqliteConnection _conn;

    public class Customer
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = null!;
        [Encrypted] public string Email { get; set; } = null!;
        [Encrypted] public byte[]? IdScan { get; set; }
    }

    public class TestCtx : DbContext
    {
        public TestCtx(DbContextOptions opt) : base(opt) { }
        public DbSet<Customer> Customers => Set<Customer>();
    }

    public EndToEndEncryptionTests()
    {
        _conn = new SqliteConnection("Filename=:memory:");
        _conn.Open();
    }

    public void Dispose() => _conn.Dispose();

    private IServiceProvider BuildServices() =>
        new ServiceCollection()
            .AddDbContext<TestCtx>(o => o.UseSqlite(_conn))
            .AddOrionVault(o =>
            {
                o.UseStaticKeys(k => k.Add(1, Key32B64));
                o.ActiveKeyId = 1;
            })
            .UseEntityFrameworkCore<TestCtx>()
            .Services
            .BuildServiceProvider();

    [Fact]
    public async Task Encrypted_string_column_round_trips_through_SQLite()
    {
        var sp = BuildServices();
        using var scope = sp.CreateScope();
        var ctx = scope.ServiceProvider.GetRequiredService<TestCtx>();
        ctx.Database.EnsureCreated();

        var id = Guid.NewGuid();
        ctx.Customers.Add(new Customer { Id = id, Name = "Ali", Email = "ali@example.com" });
        await ctx.SaveChangesAsync();
        ctx.ChangeTracker.Clear();

        var raw = await ctx.Database.SqlQuery<byte[]>($"SELECT Email FROM Customers WHERE Id = {id}").SingleAsync();
        raw[0].Should().Be(0);
        raw[1].Should().Be(1);                     // keyId 1
        raw.Length.Should().Be(30 + System.Text.Encoding.UTF8.GetByteCount("ali@example.com"));

        var loaded = await ctx.Customers.SingleAsync(c => c.Id == id);
        loaded.Email.Should().Be("ali@example.com");
    }

    [Fact]
    public async Task Encrypted_bytes_column_round_trips()
    {
        var sp = BuildServices();
        using var scope = sp.CreateScope();
        var ctx = scope.ServiceProvider.GetRequiredService<TestCtx>();
        ctx.Database.EnsureCreated();

        var id = Guid.NewGuid();
        var payload = new byte[] { 9, 8, 7, 6, 5 };
        ctx.Customers.Add(new Customer { Id = id, Name = "Veli", Email = "v@x.com", IdScan = payload });
        await ctx.SaveChangesAsync();
        ctx.ChangeTracker.Clear();

        var loaded = await ctx.Customers.SingleAsync(c => c.Id == id);
        loaded.IdScan.Should().Equal(payload);
    }

    [Fact]
    public async Task Null_encrypted_column_stays_null()
    {
        var sp = BuildServices();
        using var scope = sp.CreateScope();
        var ctx = scope.ServiceProvider.GetRequiredService<TestCtx>();
        ctx.Database.EnsureCreated();

        var id = Guid.NewGuid();
        ctx.Customers.Add(new Customer { Id = id, Name = "Z", Email = "z@x.com", IdScan = null });
        await ctx.SaveChangesAsync();
        ctx.ChangeTracker.Clear();

        var loaded = await ctx.Customers.SingleAsync(c => c.Id == id);
        loaded.IdScan.Should().BeNull();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```
dotnet test test/Moongazing.OrionVault.EntityFrameworkCore.Tests/Moongazing.OrionVault.EntityFrameworkCore.Tests.csproj --filter FullyQualifiedName~EndToEndEncryptionTests
```
Expected: FAIL — `UseEntityFrameworkCore` not defined.

- [ ] **Step 3: Implement the DI extensions**

`src/Moongazing.OrionVault.EntityFrameworkCore/DependencyInjection/OrionVaultEntityFrameworkCoreBuilderExtensions.cs`:
```csharp
namespace Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore.Internal;

public static class OrionVaultEntityFrameworkCoreBuilderExtensions
{
    /// <summary>
    /// Register OrionVault's EF Core integration bound to <typeparamref name="TDbContext"/>.
    /// </summary>
    /// <remarks>
    /// v0.1.0 supports exactly one OrionVault-bound DbContext per host. Calling
    /// this method twice registers duplicate factories; the second wins and the
    /// first DbContext's encrypted columns become misconfigured. First-class
    /// multi-DbContext support is on the v0.2 roadmap.
    /// </remarks>
    public static OrionVaultBuilder UseEntityFrameworkCore<TDbContext>(this OrionVaultBuilder builder)
        where TDbContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.TryAddSingleton<EncryptedValueConverterFactory>(sp =>
            new EncryptedValueConverterFactory(sp.GetRequiredService<IEncryptor>()));
        builder.Services.TryAddSingleton<IEncryptionConfigurator, EncryptionConfigurator>();
        builder.Services.AddSingleton<OrionVaultModelCustomizer>(sp =>
            new OrionVaultModelCustomizer(
                inner: new ModelCustomizer(new ModelCustomizerDependencies()),
                configurator: sp.GetRequiredService<IEncryptionConfigurator>()));

        return builder;
    }

    /// <summary>
    /// Attach OrionVault's model customizer to a <see cref="DbContextOptionsBuilder"/>.
    /// Call this inside the <c>(sp, opt) =&gt; ...</c> overload of <c>AddDbContext</c>.
    /// </summary>
    public static DbContextOptionsBuilder UseOrionVault(
        this DbContextOptionsBuilder builder,
        IServiceProvider serviceProvider)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(serviceProvider);

        var customizer = serviceProvider.GetRequiredService<OrionVaultModelCustomizer>();
        builder.ReplaceService<IModelCustomizer, OrionVaultModelCustomizer>();
        // The above replaces; for the replacement to actually use OUR singleton
        // (instead of letting EF Core construct a new instance), we override
        // the DbContext options' internal service provider with a child collection.
        // For v0.1.0 the cleaner approach is: have consumers omit UseOrionVault
        // entirely and rely on UseEntityFrameworkCore to register the customizer
        // via AddDbContextOptions builder. See implementation note below.

        return builder;
    }
}
```

**Implementation note (Step 3 follow-up):** EF Core 8's `IModelCustomizer` replacement via `ReplaceService<,>` requires the replacement type to be resolvable from EF Core's own internal service collection. The cleanest v0.1.0 approach is:

1. `UseEntityFrameworkCore<TDbContext>()` registers `OrionVaultModelCustomizer` as singleton in the application's DI container.
2. `UseOrionVault(sp)` calls `builder.ReplaceService<IModelCustomizer, OrionVaultModelCustomizer>()` which causes EF Core's internal SP to construct the type at first use. Because `OrionVaultModelCustomizer` has dependencies (`IEncryptionConfigurator`), we provide them via `builder.UseApplicationServiceProvider(serviceProvider)` — EF Core 8 looks up app services from this provider when constructing replaced services.

Replace the body of `UseOrionVault` with:

```csharp
builder.UseApplicationServiceProvider(serviceProvider);
builder.ReplaceService<IModelCustomizer, OrionVaultModelCustomizer>();
return builder;
```

Drop the misleading comment block and the duplicate `ReplaceService` call.

- [ ] **Step 4: Update test BuildServices to wire UseOrionVault**

Modify the test method `BuildServices`:
```csharp
private IServiceProvider BuildServices() =>
    new ServiceCollection()
        .AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, Key32B64));
            o.ActiveKeyId = 1;
        })
        .UseEntityFrameworkCore<TestCtx>()
        .Services
        .AddDbContext<TestCtx>((sp, o) => o.UseSqlite(_conn).UseOrionVault(sp))
        .BuildServiceProvider();
```

- [ ] **Step 5: Run tests — verify pass**

```
dotnet test test/Moongazing.OrionVault.EntityFrameworkCore.Tests/Moongazing.OrionVault.EntityFrameworkCore.Tests.csproj
```
Expected: 3 EndToEndEncryptionTests + 3 ModelIntegrationTests + 5 EncryptedConverterTests = 11 PASS.

- [ ] **Step 6: Commit**

```
git add src/Moongazing.OrionVault.EntityFrameworkCore/ test/Moongazing.OrionVault.EntityFrameworkCore.Tests/
git commit -m "feat: EF Core DI wiring — UseEntityFrameworkCore<TDbContext> and UseOrionVault"
git push
```

---

## Task 8: Roslyn analyzers (OV0001, OV0002, OV0003)

**Files:**
- Create: `src/Moongazing.OrionVault.Analyzers/EncryptedTypeAnalyzer.cs`
- Create: `src/Moongazing.OrionVault.Analyzers/EncryptedQueryAnalyzer.cs`
- Create: `src/Moongazing.OrionVault.Analyzers/EncryptedSymbolHelper.cs`
- Test: `test/Moongazing.OrionVault.Analyzers.Tests/EncryptedTypeAnalyzerTests.cs`
- Test: `test/Moongazing.OrionVault.Analyzers.Tests/EncryptedQueryAnalyzerTests.cs`
- Create: `test/Moongazing.OrionVault.Analyzers.Tests/Moongazing.OrionVault.Analyzers.Tests.csproj` and add to `.sln`

- [ ] **Step 1: Create the analyzer test project**

```
dotnet new xunit -n Moongazing.OrionVault.Analyzers.Tests -o test/Moongazing.OrionVault.Analyzers.Tests -f net8.0
dotnet sln add test/Moongazing.OrionVault.Analyzers.Tests/Moongazing.OrionVault.Analyzers.Tests.csproj
```

Replace the csproj with:
```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <IsPackable>false</IsPackable>
    <IsTestProject>true</IsTestProject>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" />
    <PackageReference Include="xunit" />
    <PackageReference Include="xunit.runner.visualstudio" />
    <PackageReference Include="coverlet.collector" />
    <PackageReference Include="FluentAssertions" />
    <PackageReference Include="Microsoft.CodeAnalysis.CSharp" />
    <PackageReference Include="Microsoft.CodeAnalysis.CSharp.Workspaces" />
    <PackageReference Include="Microsoft.CodeAnalysis.Analyzer.Testing" Version="1.1.2" />
    <PackageReference Include="Microsoft.CodeAnalysis.CSharp.Analyzer.Testing.XUnit" Version="1.1.2" />
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="..\..\src\Moongazing.OrionVault.Analyzers\Moongazing.OrionVault.Analyzers.csproj" />
  </ItemGroup>
</Project>
```

Add the two new analyzer testing packages to `Directory.Packages.props`:
```xml
<PackageVersion Include="Microsoft.CodeAnalysis.Analyzer.Testing" Version="1.1.2" />
<PackageVersion Include="Microsoft.CodeAnalysis.CSharp.Analyzer.Testing.XUnit" Version="1.1.2" />
```

- [ ] **Step 2: Write the failing test for OV0001**

`test/Moongazing.OrionVault.Analyzers.Tests/EncryptedTypeAnalyzerTests.cs`:
```csharp
namespace Moongazing.OrionVault.Analyzers.Tests;

using Microsoft.CodeAnalysis.CSharp.Testing.XUnit;
using Microsoft.CodeAnalysis.Testing;
using Xunit;
using Verify = Microsoft.CodeAnalysis.CSharp.Testing.CSharpAnalyzerVerifier<
    Moongazing.OrionVault.Analyzers.EncryptedTypeAnalyzer,
    Microsoft.CodeAnalysis.Testing.DefaultVerifier>;

public class EncryptedTypeAnalyzerTests
{
    [Fact]
    public async Task OV0001_fires_when_Encrypted_on_int_property()
    {
        var src = """
            namespace Moongazing.OrionVault.EntityFrameworkCore {
                public sealed class EncryptedAttribute : System.Attribute { }
            }
            namespace Demo {
                using Moongazing.OrionVault.EntityFrameworkCore;
                public class User {
                    [Encrypted] public int {|OV0001:Number|} { get; set; }
                }
            }
            """;
        await Verify.VerifyAnalyzerAsync(src);
    }

    [Fact]
    public async Task OV0001_does_not_fire_for_string_property()
    {
        var src = """
            namespace Moongazing.OrionVault.EntityFrameworkCore {
                public sealed class EncryptedAttribute : System.Attribute { }
            }
            namespace Demo {
                using Moongazing.OrionVault.EntityFrameworkCore;
                public class User {
                    [Encrypted] public string Email { get; set; } = null!;
                }
            }
            """;
        await Verify.VerifyAnalyzerAsync(src);
    }

    [Fact]
    public async Task OV0001_does_not_fire_for_byte_array_property()
    {
        var src = """
            namespace Moongazing.OrionVault.EntityFrameworkCore {
                public sealed class EncryptedAttribute : System.Attribute { }
            }
            namespace Demo {
                using Moongazing.OrionVault.EntityFrameworkCore;
                public class User {
                    [Encrypted] public byte[] Scan { get; set; } = null!;
                }
            }
            """;
        await Verify.VerifyAnalyzerAsync(src);
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

```
dotnet test test/Moongazing.OrionVault.Analyzers.Tests/Moongazing.OrionVault.Analyzers.Tests.csproj
```
Expected: FAIL — `EncryptedTypeAnalyzer` not defined.

- [ ] **Step 4: Implement helper + EncryptedTypeAnalyzer**

`src/Moongazing.OrionVault.Analyzers/EncryptedSymbolHelper.cs`:
```csharp
namespace Moongazing.OrionVault.Analyzers;

using Microsoft.CodeAnalysis;

internal static class EncryptedSymbolHelper
{
    public const string EncryptedAttributeFullName = "Moongazing.OrionVault.EntityFrameworkCore.EncryptedAttribute";
    public const string IsEncryptedMethodFullName = "Moongazing.OrionVault.EntityFrameworkCore.PropertyBuilderExtensions.IsEncrypted";

    public static bool IsEncryptedAttribute(INamedTypeSymbol symbol)
        => symbol.ToDisplayString() == EncryptedAttributeFullName;

    public static bool HasEncryptedAttribute(IPropertySymbol prop)
    {
        foreach (var attr in prop.GetAttributes())
            if (attr.AttributeClass is { } cls && IsEncryptedAttribute(cls))
                return true;
        return false;
    }
}
```

`src/Moongazing.OrionVault.Analyzers/EncryptedTypeAnalyzer.cs`:
```csharp
namespace Moongazing.OrionVault.Analyzers;

using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class EncryptedTypeAnalyzer : DiagnosticAnalyzer
{
    public static readonly DiagnosticDescriptor Rule = new(
        id: "OV0001",
        title: "[Encrypted] only supports string or byte[]",
        messageFormat: "[Encrypted] only supports string or byte[] properties. Property '{0}' has type '{1}'.",
        category: "Moongazing.OrionVault",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "OrionVault's [Encrypted] attribute is valid only on properties of type string or byte[].");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSymbolAction(AnalyzeProperty, SymbolKind.Property);
    }

    private static void AnalyzeProperty(SymbolAnalysisContext ctx)
    {
        var prop = (IPropertySymbol)ctx.Symbol;
        if (!EncryptedSymbolHelper.HasEncryptedAttribute(prop)) return;

        var t = prop.Type;
        var isString = t.SpecialType == SpecialType.System_String;
        var isByteArray = t is IArrayTypeSymbol arr && arr.ElementType.SpecialType == SpecialType.System_Byte;
        if (isString || isByteArray) return;

        ctx.ReportDiagnostic(Diagnostic.Create(
            Rule, prop.Locations[0], prop.Name, t.ToDisplayString()));
    }
}
```

- [ ] **Step 5: Run OV0001 tests — verify pass**

```
dotnet test test/Moongazing.OrionVault.Analyzers.Tests/Moongazing.OrionVault.Analyzers.Tests.csproj --filter FullyQualifiedName~EncryptedTypeAnalyzerTests
```
Expected: 3 tests PASS.

- [ ] **Step 6: Write the failing test for OV0002 + OV0003**

`test/Moongazing.OrionVault.Analyzers.Tests/EncryptedQueryAnalyzerTests.cs`:
```csharp
namespace Moongazing.OrionVault.Analyzers.Tests;

using Xunit;
using Verify = Microsoft.CodeAnalysis.CSharp.Testing.CSharpAnalyzerVerifier<
    Moongazing.OrionVault.Analyzers.EncryptedQueryAnalyzer,
    Microsoft.CodeAnalysis.Testing.DefaultVerifier>;

public class EncryptedQueryAnalyzerTests
{
    private const string Preamble = """
        using System.Linq;
        namespace Moongazing.OrionVault.EntityFrameworkCore {
            public sealed class EncryptedAttribute : System.Attribute { }
        }
        namespace Demo {
            using Moongazing.OrionVault.EntityFrameworkCore;
            public class User {
                public int Id { get; set; }
                [Encrypted] public string Email { get; set; } = "";
                public string Name { get; set; } = "";
            }
            public static class Db {
                public static IQueryable<User> Users => null!;
            }
        }
        """;

    [Fact]
    public async Task OV0002_fires_when_Where_compares_encrypted_property_to_literal()
    {
        var src = Preamble + """
            namespace Demo {
                public static class Q {
                    public static System.Collections.Generic.IEnumerable<User> Find() =>
                        Db.Users.Where(u => {|OV0002:u.Email == "a@b.com"|}).ToList();
                }
            }
            """;
        await Verify.VerifyAnalyzerAsync(src);
    }

    [Fact]
    public async Task OV0002_does_not_fire_for_unencrypted_property()
    {
        var src = Preamble + """
            namespace Demo {
                public static class Q {
                    public static System.Collections.Generic.IEnumerable<User> Find() =>
                        Db.Users.Where(u => u.Name == "Ali").ToList();
                }
            }
            """;
        await Verify.VerifyAnalyzerAsync(src);
    }

    [Fact]
    public async Task OV0003_fires_for_OrderBy_on_encrypted_property()
    {
        var src = Preamble + """
            namespace Demo {
                public static class Q {
                    public static System.Collections.Generic.IEnumerable<User> Find() =>
                        Db.Users.OrderBy(u => {|OV0003:u.Email|}).ToList();
                }
            }
            """;
        await Verify.VerifyAnalyzerAsync(src);
    }
}
```

- [ ] **Step 7: Run test to verify it fails**

```
dotnet test test/Moongazing.OrionVault.Analyzers.Tests/Moongazing.OrionVault.Analyzers.Tests.csproj --filter FullyQualifiedName~EncryptedQueryAnalyzerTests
```
Expected: FAIL — `EncryptedQueryAnalyzer` not defined.

- [ ] **Step 8: Implement EncryptedQueryAnalyzer**

`src/Moongazing.OrionVault.Analyzers/EncryptedQueryAnalyzer.cs`:
```csharp
namespace Moongazing.OrionVault.Analyzers;

using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class EncryptedQueryAnalyzer : DiagnosticAnalyzer
{
    public static readonly DiagnosticDescriptor WhereRule = new(
        id: "OV0002",
        title: "Comparing encrypted column in LINQ always returns false",
        messageFormat: "Comparing encrypted column '{0}' to a value in a LINQ query always returns false (random ciphertext per row). Use a separate HMAC index column for searchable encrypted values, or fetch and filter in memory.",
        category: "Moongazing.OrionVault",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true);

    public static readonly DiagnosticDescriptor OrderRule = new(
        id: "OV0003",
        title: "OrderBy/GroupBy on encrypted column executes client-side",
        messageFormat: "Ordering or grouping by encrypted column '{0}' executes client-side after decryption; large result sets will be slow.",
        category: "Moongazing.OrionVault",
        defaultSeverity: DiagnosticSeverity.Info,
        isEnabledByDefault: true);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(WhereRule, OrderRule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterOperationAction(AnalyzeInvocation, OperationKind.Invocation);
    }

    private static readonly string[] WhereMethods = { "Where", "First", "FirstOrDefault", "Single", "SingleOrDefault", "Any", "Count" };
    private static readonly string[] OrderMethods = { "OrderBy", "OrderByDescending", "ThenBy", "ThenByDescending", "GroupBy" };

    private static void AnalyzeInvocation(OperationAnalysisContext ctx)
    {
        var invocation = (IInvocationOperation)ctx.Operation;
        var method = invocation.TargetMethod;
        if (method.ContainingType?.ToDisplayString() != "System.Linq.Queryable" &&
            method.ContainingType?.ToDisplayString() != "System.Linq.Enumerable")
            return;

        if (System.Array.IndexOf(OrderMethods, method.Name) >= 0)
        {
            ScanLambdaForEncryptedMember(invocation, ctx, OrderRule);
            return;
        }
        if (System.Array.IndexOf(WhereMethods, method.Name) >= 0)
        {
            ScanPredicateForComparison(invocation, ctx);
        }
    }

    private static void ScanLambdaForEncryptedMember(
        IInvocationOperation invocation, OperationAnalysisContext ctx, DiagnosticDescriptor rule)
    {
        foreach (var arg in invocation.Arguments)
        {
            var lambda = arg.Value as IDelegateCreationOperation;
            if (lambda?.Target is not IAnonymousFunctionOperation anon) continue;
            foreach (var prop in CollectEncryptedMembers(anon))
                ctx.ReportDiagnostic(Diagnostic.Create(rule, prop.Syntax.GetLocation(), prop.Property.Name));
        }
    }

    private static void ScanPredicateForComparison(
        IInvocationOperation invocation, OperationAnalysisContext ctx)
    {
        foreach (var arg in invocation.Arguments)
        {
            var lambda = arg.Value as IDelegateCreationOperation;
            if (lambda?.Target is not IAnonymousFunctionOperation anon) continue;

            foreach (var op in anon.Body.Descendants())
            {
                if (op is not IBinaryOperation bin) continue;
                if (bin.OperatorKind is not (BinaryOperatorKind.Equals or BinaryOperatorKind.NotEquals)) continue;

                var lhs = bin.LeftOperand as IPropertyReferenceOperation;
                var rhs = bin.RightOperand as IPropertyReferenceOperation;
                if (lhs is not null && EncryptedSymbolHelper.HasEncryptedAttribute(lhs.Property))
                    ctx.ReportDiagnostic(Diagnostic.Create(WhereRule, bin.Syntax.GetLocation(), lhs.Property.Name));
                else if (rhs is not null && EncryptedSymbolHelper.HasEncryptedAttribute(rhs.Property))
                    ctx.ReportDiagnostic(Diagnostic.Create(WhereRule, bin.Syntax.GetLocation(), rhs.Property.Name));
            }
        }
    }

    private static IEnumerable<IPropertyReferenceOperation> CollectEncryptedMembers(IAnonymousFunctionOperation anon)
    {
        foreach (var op in anon.Body.Descendants())
        {
            if (op is IPropertyReferenceOperation pref && EncryptedSymbolHelper.HasEncryptedAttribute(pref.Property))
                yield return pref;
        }
    }
}
```

- [ ] **Step 9: Run all analyzer tests — verify pass**

```
dotnet test test/Moongazing.OrionVault.Analyzers.Tests/Moongazing.OrionVault.Analyzers.Tests.csproj
```
Expected: 3 OV0001 + 3 OV0002/OV0003 = 6 PASS.

- [ ] **Step 10: Verify analyzer assembly is bundled into the OrionVault nupkg**

```
dotnet pack src/Moongazing.OrionVault/Moongazing.OrionVault.csproj -c Release
```
Then inspect the produced nupkg:
```
unzip -l src/Moongazing.OrionVault/bin/Release/Moongazing.OrionVault.0.1.0.nupkg | grep analyzers
```
Expected: shows `analyzers/dotnet/cs/Moongazing.OrionVault.Analyzers.dll`.

- [ ] **Step 11: Commit**

```
git add src/Moongazing.OrionVault.Analyzers/ test/Moongazing.OrionVault.Analyzers.Tests/ Directory.Packages.props Moongazing.OrionVault.sln
git commit -m "feat: Roslyn analyzers OV0001 (type), OV0002 (where), OV0003 (order/group)"
git push
```

---

## Task 9: Testing package

**Files:**
- Create: `src/Moongazing.OrionVault.Testing/TestKeyProvider.cs`
- Create: `src/Moongazing.OrionVault.Testing/PlaintextEncryptor.cs`
- Create: `src/Moongazing.OrionVault.Testing/EncryptionAssertions.cs`
- Create: `src/Moongazing.OrionVault.Testing/DependencyInjection/OrionVaultTestingBuilderExtensions.cs`
- Test: `test/Moongazing.OrionVault.Testing.Tests/TestingPackageTests.cs`

- [ ] **Step 1: Write the failing test**

`test/Moongazing.OrionVault.Testing.Tests/TestingPackageTests.cs`:
```csharp
namespace Moongazing.OrionVault.Testing.Tests;

using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Testing;
using Moongazing.OrionVault.Testing.DependencyInjection;
using Xunit;

public class TestingPackageTests
{
    [Fact]
    public void TestKeyProvider_Default_returns_active_key_id_1_and_zero_key()
    {
        var sut = TestKeyProvider.Default;
        sut.ActiveKeyId.Should().Be(1);
        sut.TryGetKey(1).Should().NotBeNull();
        sut.TryGetKey(1)!.Value.Length.Should().Be(32);
        sut.TryGetKey(99).Should().BeNull();
    }

    [Fact]
    public void TestKeyProvider_Add_registers_an_extra_key()
    {
        var sut = new TestKeyProvider(activeKeyId: 1);
        var k2 = new byte[32]; k2[0] = 0xFF;
        sut.Add(2, k2);

        sut.TryGetKey(2)!.Value.Span[0].Should().Be(0xFF);
    }

    [Fact]
    public void PlaintextEncryptor_round_trips_string_with_30_byte_header()
    {
        var sut = new PlaintextEncryptor();
        var ct = sut.EncryptString("hello");
        ct.Length.Should().Be(30 + 5);
        sut.DecryptString(ct).Should().Be("hello");
    }

    [Fact]
    public void EncryptionAssertions_IsEncryptedWithKey_passes_for_correct_key()
    {
        var prov = TestKeyProvider.Default;
        var enc = new Moongazing.OrionVault.Internal.AesGcmEncryptor(prov, new Moongazing.OrionVault.Diagnostics.OrionVaultDiagnostics());
        var ct = enc.EncryptString("x");

        EncryptionAssertions.IsEncrypted(ct);
        EncryptionAssertions.ReadKeyId(ct).Should().Be(1);
        EncryptionAssertions.IsEncryptedWithKey(ct, expectedKeyId: 1);
    }

    [Fact]
    public void UseTestKeys_extension_wires_TestKeyProvider()
    {
        var sp = new ServiceCollection()
            .AddOrionVault(o => { /* configure below via extension */ })
            .UseTestKeys()
            .Services
            .BuildServiceProvider();

        sp.GetRequiredService<IKeyProvider>().Should().BeOfType<TestKeyProvider>();
    }
}
```

(The `UseTestKeys` test as written conflicts with `AddOrionVault`'s requirement that keys be registered upfront — see implementation note below.)

- [ ] **Step 2: Run test to verify it fails**

```
dotnet test test/Moongazing.OrionVault.Testing.Tests/Moongazing.OrionVault.Testing.Tests.csproj
```
Expected: FAIL — types not defined.

- [ ] **Step 3: Implement TestKeyProvider**

`src/Moongazing.OrionVault.Testing/TestKeyProvider.cs`:
```csharp
namespace Moongazing.OrionVault.Testing;

using System.Collections.Concurrent;
using Moongazing.OrionVault.Abstractions;

public sealed class TestKeyProvider : IKeyProvider
{
    private readonly ConcurrentDictionary<short, byte[]> _keys = new();

    public TestKeyProvider(short activeKeyId = 1)
    {
        ActiveKeyId = activeKeyId;
        _keys[activeKeyId] = new byte[32];   // all zeros, deterministic
    }

    public static TestKeyProvider Default { get; } = new(activeKeyId: 1);

    public short ActiveKeyId { get; }

    public void Add(short keyId, ReadOnlyMemory<byte> key)
    {
        if (key.Length != 32)
            throw new ArgumentException("Key must be exactly 32 bytes.", nameof(key));
        _keys[keyId] = key.ToArray();
    }

    public ReadOnlyMemory<byte>? TryGetKey(short keyId)
        => _keys.TryGetValue(keyId, out var k) ? k : null;
}
```

- [ ] **Step 4: Implement PlaintextEncryptor**

`src/Moongazing.OrionVault.Testing/PlaintextEncryptor.cs`:
```csharp
namespace Moongazing.OrionVault.Testing;

using System.Text;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Internal;

/// <summary>
/// Drop-in <see cref="IEncryptor"/> that writes the standard 30-byte header
/// followed by the identity body (no actual encryption). The auth tag region
/// is zeros. Use only in tests that need to inspect ciphertext layout without
/// running real crypto.
/// </summary>
public sealed class PlaintextEncryptor : IEncryptor
{
    public byte[] EncryptString(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return EncryptBytes(Encoding.UTF8.GetBytes(plaintext));
    }

    public string DecryptString(byte[] ciphertext) => Encoding.UTF8.GetString(DecryptBytes(ciphertext));

    public byte[] EncryptBytes(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var output = new byte[CipherFormat.HeaderSize + CipherFormat.TagSize + plaintext.Length];
        CipherFormat.WriteHeader(output, keyId: 0, new byte[CipherFormat.NonceSize]);
        plaintext.CopyTo(output, CipherFormat.HeaderSize + CipherFormat.TagSize);
        return output;
    }

    public byte[] DecryptBytes(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        if (ciphertext.Length < CipherFormat.MinimumCiphertextLength)
            throw new ArgumentException("Ciphertext too short.", nameof(ciphertext));
        return ciphertext[(CipherFormat.HeaderSize + CipherFormat.TagSize)..];
    }
}
```

- [ ] **Step 5: Implement EncryptionAssertions**

`src/Moongazing.OrionVault.Testing/EncryptionAssertions.cs`:
```csharp
namespace Moongazing.OrionVault.Testing;

using Moongazing.OrionVault.Internal;

public static class EncryptionAssertions
{
    public static void IsEncrypted(byte[] columnValue)
    {
        ArgumentNullException.ThrowIfNull(columnValue);
        if (columnValue.Length < CipherFormat.MinimumCiphertextLength)
            throw new Xunit.Sdk.XunitException(
                $"Expected encrypted column (>= {CipherFormat.MinimumCiphertextLength} bytes), got {columnValue.Length} bytes.");
    }

    public static short ReadKeyId(byte[] columnValue)
    {
        IsEncrypted(columnValue);
        return CipherFormat.ReadKeyId(columnValue);
    }

    public static void IsEncryptedWithKey(byte[] columnValue, short expectedKeyId)
    {
        var actual = ReadKeyId(columnValue);
        if (actual != expectedKeyId)
            throw new Xunit.Sdk.XunitException(
                $"Expected encrypted with key id {expectedKeyId}, got {actual}.");
    }
}
```

Add `<PackageReference Include="xunit.assert" Version="2.9.2" />` to the Testing csproj for `Xunit.Sdk.XunitException`, and the matching `PackageVersion` to `Directory.Packages.props`.

- [ ] **Step 6: Implement UseTestKeys extension**

The clean DI shape: `AddOrionVaultForTesting()` replaces `AddOrionVault()` entirely so the no-keys-registered requirement doesn't fire. Replace the test from Step 1 (last assertion) and the extension:

`src/Moongazing.OrionVault.Testing/DependencyInjection/OrionVaultTestingBuilderExtensions.cs`:
```csharp
namespace Moongazing.OrionVault.Testing.DependencyInjection;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Internal;

public static class OrionVaultTestingBuilderExtensions
{
    /// <summary>
    /// Register a complete OrionVault setup using <see cref="TestKeyProvider.Default"/>
    /// and the real AES-GCM encryptor. Use in tests instead of <c>AddOrionVault</c>.
    /// </summary>
    public static OrionVaultBuilder AddOrionVaultForTesting(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<OrionVaultDiagnostics>();
        services.AddSingleton<IKeyProvider>(TestKeyProvider.Default);
        services.AddSingleton<IEncryptor, AesGcmEncryptor>();
        return new OrionVaultBuilder(services);
    }
}
```

Update the failing test in Step 1 to:
```csharp
[Fact]
public void AddOrionVaultForTesting_wires_TestKeyProvider_and_round_trips_a_value()
{
    var sp = new ServiceCollection()
        .AddOrionVaultForTesting()
        .Services
        .BuildServiceProvider();
    sp.GetRequiredService<IKeyProvider>().Should().BeOfType<TestKeyProvider>();
    var enc = sp.GetRequiredService<IEncryptor>();
    enc.DecryptString(enc.EncryptString("x")).Should().Be("x");
}
```

- [ ] **Step 7: Run all Testing tests — verify pass**

```
dotnet test test/Moongazing.OrionVault.Testing.Tests/Moongazing.OrionVault.Testing.Tests.csproj
```
Expected: 5 tests PASS.

- [ ] **Step 8: Commit**

```
git add src/Moongazing.OrionVault.Testing/ test/Moongazing.OrionVault.Testing.Tests/ Directory.Packages.props
git commit -m "feat: Testing package — TestKeyProvider, PlaintextEncryptor, EncryptionAssertions, AddOrionVaultForTesting"
git push
```

---

## Task 10: Sample app

**Files:**
- Create: `sample/Moongazing.OrionVault.Sample/Customer.cs`
- Create: `sample/Moongazing.OrionVault.Sample/SampleDbContext.cs`
- Create: `sample/Moongazing.OrionVault.Sample/Program.cs`

- [ ] **Step 1: Write Customer entity**

`sample/Moongazing.OrionVault.Sample/Customer.cs`:
```csharp
namespace Moongazing.OrionVault.Sample;

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

- [ ] **Step 2: Write DbContext**

`sample/Moongazing.OrionVault.Sample/SampleDbContext.cs`:
```csharp
namespace Moongazing.OrionVault.Sample;

using Microsoft.EntityFrameworkCore;

public class SampleDbContext : DbContext
{
    public SampleDbContext(DbContextOptions<SampleDbContext> opt) : base(opt) { }
    public DbSet<Customer> Customers => Set<Customer>();
}
```

- [ ] **Step 3: Write Program.cs**

`sample/Moongazing.OrionVault.Sample/Program.cs`:
```csharp
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.EntityFrameworkCore.DependencyInjection;
using Moongazing.OrionVault.Sample;

var services = new ServiceCollection()
    .AddLogging(b => b.AddConsole().SetMinimumLevel(LogLevel.Warning))
    .AddOrionVault(o =>
    {
        o.UseStaticKeys(k =>
            k.Add(keyId: 1, base64Key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        o.ActiveKeyId = 1;
    })
    .UseEntityFrameworkCore<SampleDbContext>()
    .Services
    .AddDbContext<SampleDbContext>((sp, opt) =>
        opt.UseSqlite("Data Source=sample.db").UseOrionVault(sp))
    .BuildServiceProvider();

if (File.Exists("sample.db")) File.Delete("sample.db");

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
Console.WriteLine($"Raw bytes in DB (first 6 hex): {Convert.ToHexString(raw[..6])}");
Console.WriteLine($"Raw length: {raw.Length} bytes (30 header + {raw.Length - 30} body)");

db.ChangeTracker.Clear();
var loaded = await db.Customers.FirstAsync();
Console.WriteLine($"Decrypted Email: {loaded.Email}");
Console.WriteLine($"Decrypted IbanLast4: {loaded.IbanLast4}");
```

- [ ] **Step 4: Run the sample**

```
dotnet run --project sample/Moongazing.OrionVault.Sample/Moongazing.OrionVault.Sample.csproj
```
Expected output:
```
Yazıldı.
Raw bytes in DB (first 6 hex): 0001XXXXXXXX
Raw length: 45 bytes (30 header + 15 body)
Decrypted Email: ali@example.com
Decrypted IbanLast4: 1234
```
The `0001` prefix confirms keyId 1; the body length matches UTF-8 byte count of "ali@example.com" (15 bytes).

- [ ] **Step 5: Commit**

```
git add sample/Moongazing.OrionVault.Sample/
git commit -m "feat: sample console app demonstrating encrypt → raw inspect → decrypt round-trip"
git push
```

---

## Task 11: Documentation polish

**Files:**
- Modify: `README.md` (full rewrite from Task 0 placeholder)
- Create: `ROADMAP.md`
- Create: `CHANGELOG.md` (draft — finalised in Task 12)
- Create: `src/Moongazing.OrionVault/docs/README.md` (per-package README packed into nupkg)
- Create: `src/Moongazing.OrionVault.EntityFrameworkCore/docs/README.md`
- Create: `src/Moongazing.OrionVault.Testing/docs/README.md`
- Modify: each src csproj — add `<PackageReadmeFile>README.md</PackageReadmeFile>` + `<None Include="docs/README.md" Pack="true" PackagePath="\" />`

- [ ] **Step 1: Write the root README**

Replace `README.md` with the full family-style README. Use OrionPatch's README as the structural template (intro, quickstart, comparison vs alternatives, telemetry, family cross-link). Key sections to include:

- Title + tagline + badges (NuGet version, downloads, target frameworks, license, build)
- "What it does" — three sentences explaining column encryption at rest, threat model, when to use it
- Quickstart (install → configure DI → mark property with `[Encrypted]` → done)
- "How it compares" — short table vs `Microsoft.AspNetCore.DataProtection`, `EntityFrameworkCore.Encrypt`, manual `ValueConverter`
- "Cipher format" — ASCII art of `[keyId|nonce|tag|ciphertext]`
- "Key rotation" — multi-key read, single-key write, manual drain procedure
- "Searchable encrypted columns" — explain HMAC index pattern as workaround for OV0002
- "Telemetry" — list ActivitySource + 5 counters + 1 histogram with example OTel hookup
- "Veil vs OrionVault" — one-paragraph clarification (Veil = output masking, OrionVault = storage encryption, complementary)
- "Family" — links to all 6 sibling packages
- License, contributing, roadmap link

Length target: roughly the same as OrionPatch's README (~600 lines).

Use OrionPatch's README directly as a structural starting point:
```
cp "c:/Users/Tunahan Ali Ozturk/OneDrive - PEAKUP/Desktop/OrionPatch/README.md" README.md
```
Then rewrite section-by-section for OrionVault. **Do not** leave any OrionPatch-specific copy in place.

- [ ] **Step 2: Write ROADMAP.md (mirror spec §16)**

`ROADMAP.md`:
```markdown
# OrionVault Roadmap

OrionVault follows the same release rhythm as the rest of the Orion family: quarterly minor versions, patch releases as needed, and a v1.0 only when the public API surface is stable.

## v0.1.0 — 2026-Q2 (current)
- Column encryption for `string` and `byte[]` via AES-256-GCM
- Multi-key read, single-key write key rotation
- `[Encrypted]` attribute and `IsEncrypted()` fluent API
- Roslyn analyzer (OV0001, OV0002, OV0003)
- Testing package with deterministic `TestKeyProvider`
- Telemetry: 1 ActivitySource, 5 counters, 1 histogram

## v0.2 — 2026-Q4
- AWS KMS provider (`Moongazing.OrionVault.AwsKms`)
- Azure Key Vault provider (`Moongazing.OrionVault.AzureKeyVault`)
- Background re-encryption hosted service for draining retired keys
- First-class multi-DbContext support

## v0.3 — 2027-Q1
- Numeric, DateTime, decimal type support
- Searchable encrypted columns via HMAC index property convention
- Migration helper for converting existing plaintext columns

## v0.4 — 2027-Q1/Q2
- Windows DPAPI provider (`Moongazing.OrionVault.Dpapi`)
- HashiCorp Vault provider (`Moongazing.OrionVault.HashiCorp`)
- Per-tenant key partitioning

## v1.0 — 2027-Q2
- Public API surface freeze
- Production-hardened benchmarks
- Compliance documentation (KVKK, GDPR, PCI-DSS mapping)
```

- [ ] **Step 3: Write CHANGELOG.md (draft)**

`CHANGELOG.md`:
```markdown
# Changelog

All notable changes to OrionVault are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.0] — 2026-05-24

### Added
- Initial release. Column-level transparent data encryption at rest for EF Core.
- `IEncryptor`, `IKeyProvider`, `IEncryptionConfigurator` core abstractions.
- AES-256-GCM cipher with `[keyId(2) | nonce(12) | tag(16) | ciphertext(N)]` on-disk layout.
- In-config `StaticKeyProvider`. Multi-key read, single-key write key rotation.
- `[Encrypted]` attribute and `IsEncrypted()` fluent API for marking properties.
- Automatic value-converter wiring via `IModelCustomizer` decoration.
- `Moongazing.OrionVault.Testing` package: `TestKeyProvider`, `PlaintextEncryptor`, `EncryptionAssertions`, `AddOrionVaultForTesting()` extension.
- Bundled Roslyn analyzer: OV0001 (type), OV0002 (Where comparison), OV0003 (OrderBy/GroupBy).
- Telemetry via `OrionVault.Diagnostics`: `ActivitySource`, 5 counters, 1 histogram.
- Multi-target net8.0 / net9.0 / net10.0.

### Known limitations
- Single OrionVault-bound DbContext per host. First-class multi-DbContext support is on the v0.2 roadmap.
- Manual re-encryption only (SQL `UPDATE` round-trip through value converter). Background drain hosted service is on the v0.2 roadmap.
- Only `string` and `byte[]` CLR types are supported. Numeric/DateTime/decimal/JSON types are on the v0.3 roadmap.
- No cloud KMS providers yet (AWS, Azure, GCP, HashiCorp, DPAPI). All planned for v0.2 / v0.4 roadmap.

[Unreleased]: https://github.com/tunahanaliozturk/OrionVault/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tunahanaliozturk/OrionVault/releases/tag/v0.1.0
```

- [ ] **Step 4: Write per-package READMEs (3 files)**

Each goes into `src/<package>/docs/README.md` and gets packed into the corresponding nupkg.

`src/Moongazing.OrionVault/docs/README.md`:
```markdown
# Moongazing.OrionVault

Core package: AES-256-GCM column encryption primitives, in-config static key provider, telemetry, and the bundled Roslyn analyzer.

For full documentation, EF Core integration, and quickstart see https://github.com/tunahanaliozturk/OrionVault.
```

`src/Moongazing.OrionVault.EntityFrameworkCore/docs/README.md`:
```markdown
# Moongazing.OrionVault.EntityFrameworkCore

EF Core integration for OrionVault: value converters, `[Encrypted]` attribute, `IsEncrypted()` fluent API, model customizer, and DbContext DI extensions.

Install both this package and `Moongazing.OrionVault` to enable transparent column encryption in your EF Core model.

For full documentation see https://github.com/tunahanaliozturk/OrionVault.
```

`src/Moongazing.OrionVault.Testing/docs/README.md`:
```markdown
# Moongazing.OrionVault.Testing

Test helpers for OrionVault: deterministic `TestKeyProvider`, `PlaintextEncryptor` for layout inspection, `EncryptionAssertions`, and `AddOrionVaultForTesting()` DI extension.

For full documentation see https://github.com/tunahanaliozturk/OrionVault.
```

- [ ] **Step 5: Wire per-package READMEs into csproj**

For each of the 3 src csproj, add inside `<ItemGroup>`:
```xml
<None Include="docs/README.md" Pack="true" PackagePath="\" />
```

The `<PackageReadmeFile>README.md</PackageReadmeFile>` is already inherited from `Directory.Build.props` (Task 0).

- [ ] **Step 6: Verify pack produces nupkg with README inside**

```
dotnet pack Moongazing.OrionVault.sln -c Release
unzip -l src/Moongazing.OrionVault/bin/Release/Moongazing.OrionVault.0.1.0.nupkg | grep -E "(README|icon|analyzers)"
```
Expected: each nupkg contains `README.md`, `icon.png`, and (for the core) `analyzers/dotnet/cs/Moongazing.OrionVault.Analyzers.dll`.

- [ ] **Step 7: Commit**

```
git add README.md ROADMAP.md CHANGELOG.md src/*/docs/ src/*/Moongazing.OrionVault*.csproj
git commit -m "docs: polish README, ROADMAP, CHANGELOG, per-package READMEs"
git push
```

---

## Task 12: First release v0.1.0

**Files:**
- Verify: `CHANGELOG.md` v0.1.0 entry from Task 11 (no changes needed unless gaps found)
- Modify: 5 sibling READMEs (cross-link OrionVault into the family list)

This task is run autonomously, end-to-end, without further user check-ins. Follow the OrionPatch release flow exactly — it is the proven precedent.

- [ ] **Step 1: Verify build and full test suite**

```
dotnet build Moongazing.OrionVault.sln -c Release
dotnet test Moongazing.OrionVault.sln -c Release --no-build
```
Expected: build succeeds with zero errors. All tests pass across all 4 test projects.

If any test fails, STOP and fix before release — do not push the tag.

- [ ] **Step 2: Verify CHANGELOG.md v0.1.0 entry is finalised**

Open `CHANGELOG.md`, confirm the v0.1.0 section matches Task 11 Step 3 verbatim. No "[Unreleased]" content should remain above it. Today's date (`2026-05-24`) is correct.

- [ ] **Step 3: Push CHANGELOG (if not already pushed in Task 11)**

```
git status
```
If `CHANGELOG.md` is dirty:
```
git add CHANGELOG.md
git commit -m "docs: finalise v0.1.0 changelog entry"
git push origin main
```

- [ ] **Step 4: Create and push the v0.1.0 tag**

```
git tag -a v0.1.0 -m "OrionVault v0.1.0 — first release"
git push origin v0.1.0
```

- [ ] **Step 5: Create GitHub Release (triggers NuGet publish)**

Write release notes to `c:/tmp/orionvault-v0.1.0-release-notes.md` mirroring the CHANGELOG v0.1.0 section but written as an announcement. Sincere first person OK ("This is the first release of OrionVault."). **No emojis. No em-dashes. No buzzwords.**

```
gh release create v0.1.0 \
  --repo tunahanaliozturk/OrionVault \
  --title "OrionVault v0.1.0" \
  --notes-file /c/tmp/orionvault-v0.1.0-release-notes.md
```

- [ ] **Step 6: Watch the NuGet publish workflow**

```
gh run watch --repo tunahanaliozturk/OrionVault
```
Expected: `release.yml` workflow run completes with `success`. Three packages pushed to NuGet.

- [ ] **Step 7: Verify all 3 packages are live on NuGet**

```
curl -s https://api.nuget.org/v3-flatcontainer/moongazing.orionvault/index.json
curl -s https://api.nuget.org/v3-flatcontainer/moongazing.orionvault.entityframeworkcore/index.json
curl -s https://api.nuget.org/v3-flatcontainer/moongazing.orionvault.testing/index.json
```
Each call should return a JSON with `"versions": ["0.1.0"]`. NuGet indexing can take 5-10 minutes; if the package isn't listed yet after Step 6 completed, note it and proceed — don't block.

- [ ] **Step 8: Apply branch protection to main**

Write the protection JSON to a temp file:
```
cat > /c/tmp/orionvault-branch-protection.json << 'JSON'
{
  "required_status_checks": null,
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 0,
    "dismiss_stale_reviews": false,
    "require_code_owner_reviews": false
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": false,
  "lock_branch": false,
  "allow_fork_syncing": true
}
JSON
```

Apply:
```
gh api -X PUT repos/tunahanaliozturk/OrionVault/branches/main/protection \
  --input /c/tmp/orionvault-branch-protection.json
```

- [ ] **Step 9: Cross-link OrionVault in 5 sibling READMEs**

Sibling repos and their default branches:

| Repo | Branch | Local path |
|------|--------|------------|
| OrionGuard | `master` (protected) | `c:/Users/Tunahan Ali Ozturk/OneDrive - PEAKUP/Desktop/OrionGuard` |
| OrionAudit | `master` (protected) | `c:/Users/Tunahan Ali Ozturk/OneDrive - PEAKUP/Desktop/OrionAudit` |
| OrionLock | `main` (protected) | `c:/Users/Tunahan Ali Ozturk/OneDrive - PEAKUP/Desktop/OrionLock` |
| OrionKey | `main` (protected) | `c:/Users/Tunahan Ali Ozturk/OneDrive - PEAKUP/Desktop/OrionKey` |
| OrionPatch | `main` (protected) | `c:/Users/Tunahan Ali Ozturk/OneDrive - PEAKUP/Desktop/OrionPatch` |

For each sibling repo:

1. `cd` to the repo. Read its current README. Find the family / related-packages section (each has one — match its exact style).
2. Add OrionVault row matching the format used by that README:
   - Name: `Moongazing.OrionVault`
   - One-line: `Column-level transparent data encryption at rest for EF Core.`
   - NuGet link: `https://www.nuget.org/packages/Moongazing.OrionVault`
   - GitHub link: `https://github.com/tunahanaliozturk/OrionVault`
3. Create branch:
   ```
   git checkout -b docs/add-orionvault-crosslink
   ```
4. Commit (no co-author trailer):
   ```
   git add README.md
   git commit -m "docs: cross-link OrionVault in family list"
   ```
5. Push and open PR:
   ```
   git push -u origin docs/add-orionvault-crosslink
   gh pr create --title "Cross-link OrionVault in family list" --body "Adds OrionVault to the Orion family list following its v0.1.0 release on NuGet."
   ```
6. Merge with admin override (branches are protected):
   ```
   gh pr merge --squash --delete-branch --admin
   ```

- [ ] **Step 10: Reporting**

Report back with:
- Confirmation that v0.1.0 tag was pushed
- GitHub Release URL
- NuGet workflow run status
- Whether all 3 packages are confirmed live on NuGet
- Branch protection applied: yes/no
- 5 sibling PRs created and merged: list each PR URL
- Any deviations or issues encountered

Status options: DONE / DONE_WITH_CONCERNS / NEEDS_CONTEXT / BLOCKED.

---

## Self-Review Notes

**1. Spec coverage check** (run after writing the plan):
- §1 Purpose / Out of scope → Tasks 1-9 cover in-scope; out-of-scope items are roadmap entries in Task 11 ROADMAP.md.
- §2 Package layout → Task 0 scaffolds all 3 src + Analyzers + 3 test + 1 sample (8 projects).
- §3 Core abstractions → Task 1.
- §4 Cipher format → Task 2 (`CipherFormat`, `AesGcmEncryptor`).
- §5 Key rotation → Task 2 tests (`Decrypt_reads_old_key_for_legacy_ciphertext`, `Encrypt_uses_ActiveKeyId`); Task 3 (StaticKeysBuilder Add + ActiveKeyId validation).
- §6 Configuration API → Task 5 ([Encrypted] attribute), Task 6 (IsEncrypted fluent + configurator), Task 7 (DI wiring).
- §7 EF Core internals → Task 5 (converters, factory), Task 6 (customizer).
- §8 Roslyn analyzer → Task 8 (OV0001 + OV0002 + OV0003).
- §9 Telemetry → Task 4.
- §10 Error handling → Task 1 (exception hierarchy), Tasks 2/3/5/6 throw appropriately.
- §11 Testing package → Task 9.
- §12 Sample → Task 10.
- §13 TFM/dependencies → Task 0 (Directory.Packages.props, csproj TFMs).
- §14 Solution structure → Task 0.
- §15 CI/CD → Task 0 (workflows), Task 12 (release execution).
- §16 Roadmap → Task 11 (ROADMAP.md).

All spec sections have a task. No gaps.

**2. Placeholder scan:** searched for "TBD", "TODO", "implement later", "similar to" — none found. Every code step shows complete code.

**3. Type consistency check:**
- `IKeyProvider.TryGetKey` returns `ReadOnlyMemory<byte>?` — consistent across Tasks 1, 2, 3, 9.
- `IKeyProvider.ActiveKeyId` is `short` — consistent.
- `IEncryptor` method signatures `EncryptString(string) → byte[]` and `DecryptString(byte[]) → string` consistent across Tasks 1, 2, 4, 5, 9.
- `CipherFormat.HeaderSize = 14` (keyId 2 + nonce 12), `MinimumCiphertextLength = 30` (header 14 + tag 16) — consistent across Tasks 2, 7 (raw[0] / raw[1] / raw.Length assertions), 9 (PlaintextEncryptor), 10 (sample output).
- `[Encrypted]` attribute is in namespace `Moongazing.OrionVault.EntityFrameworkCore` — Tasks 5, 6, 7, 8, 10 all consistent.
- `OrionVaultBuilder.Services` property — Tasks 3, 7, 9 all use it.

No inconsistencies.

---

## Execution Handoff

Plan saved to `docs/superpowers/plans/2026-05-24-orionvault-v0.1.0.md`.

Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task with two-stage review (spec compliance then code quality) between tasks. Same approach as the OrionPatch shipment.
2. **Inline Execution** — execute tasks in this session using `superpowers:executing-plans` with batch checkpoints.

Which approach?

