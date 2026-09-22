namespace Moongazing.OrionVault.Testing.Tests;

using System.Reflection;
using System.Runtime.CompilerServices;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Testing;
using Moongazing.OrionVault.Testing.DependencyInjection;
using Xunit;

#pragma warning disable OV9000 // this assembly exists to exercise the zero-key provider

/// <summary>
/// Opts this test assembly in to the zero-key test double once, before any test runs. A consumer
/// does the same thing in their own test project - which is the point: nothing in a shipped build
/// ever executes this.
/// </summary>
internal static class TestingAssemblyInitializer
{
    [ModuleInitializer]
    internal static void Enable() => DangerousTestKeyProvider.Enable();
}

public class TestingPackageTests
{
    [Fact]
    public void TestKeyProvider_Default_returns_active_key_id_1_and_zero_key()
    {
        var sut = DangerousTestKeyProvider.Default;
        sut.ActiveKeyId.Should().Be(1);
        sut.TryGetKey(1).Should().NotBeNull();
        sut.TryGetKey(1)!.Value.Length.Should().Be(32);
        sut.TryGetKey(99).Should().BeNull();
    }

    [Fact]
    public void TestKeyProvider_Add_registers_an_extra_key()
    {
        var sut = new DangerousTestKeyProvider(activeKeyId: 1);
        var k2 = new byte[32]; k2[0] = 0xFF;
        sut.Add(2, k2);

        sut.TryGetKey(2)!.Value.Span[0].Should().Be(0xFF);
    }

    [Fact]
    public void EncryptionAssertions_IsEncryptedWithKey_passes_for_correct_key()
    {
        var sp = new ServiceCollection().AddOrionVaultForTesting().Services.BuildServiceProvider();
        var enc = sp.GetRequiredService<IEncryptor>();
        var ct = enc.EncryptString("x");

        EncryptionAssertions.IsEncrypted(ct);
        EncryptionAssertions.ReadKeyId(ct).Should().Be(1);
        EncryptionAssertions.IsEncryptedWithKey(ct, expectedKeyId: 1);
    }

    [Fact]
    public void AddOrionVaultForTesting_wires_TestKeyProvider_and_round_trips_a_value()
    {
        var sp = new ServiceCollection()
            .AddOrionVaultForTesting()
            .Services
            .BuildServiceProvider();
        sp.GetRequiredService<IKeyProvider>().Should().BeOfType<DangerousTestKeyProvider>();
        var enc = sp.GetRequiredService<IEncryptor>();
        enc.DecryptString(enc.EncryptString("x")).Should().Be("x");
    }

    // --- Regression guards: the package must not be usable by accident. ---

    [Fact]
    public void Zero_key_provider_refuses_to_construct_without_an_explicit_opt_in()
    {
        // The module initializer opted this assembly in, so flip it back off for the duration.
        // Parallelization is disabled for this assembly (see AssemblyInfo) because an AppContext
        // switch is process-global.
        AppContext.SetSwitch(DangerousTestKeyProvider.EnableSwitchName, false);
        try
        {
            var ex = Assert.Throws<InvalidOperationException>(() => new DangerousTestKeyProvider());
            ex.Message.Should().Contain("all-zero AES key");

            // The message is the whole support experience: someone hitting this is mid-test-run,
            // so both remedies must be in it verbatim and copy-pasteable, not described.
            ex.Message.Should().Contain("DangerousTestKeyProvider.Enable();");
            ex.Message.Should().Contain(
                $"""<RuntimeHostConfigurationOption Include="{DangerousTestKeyProvider.EnableSwitchName}" Value="true" />""");
            ex.Message.Should().Contain("PrivateAssets=\"all\"");
        }
        finally
        {
            DangerousTestKeyProvider.Enable();
        }
    }

    [Fact]
    public void Default_works_after_Enable_in_the_same_process_that_already_saw_the_throw()
    {
        // Walks the exact sequence the failure message tells a developer to walk: touch Default,
        // read the exception, call Enable(), touch it again - and it must work WITHOUT restarting
        // the host. A gate that throws from inside a Lazy<T> caches that exception for the life of
        // the process, so the message would be prescribing a fix that cannot work in a test host
        // that has already touched Default, or in any in-process retry.
        AppContext.SetSwitch(DangerousTestKeyProvider.EnableSwitchName, false);
        try
        {
            Assert.Throws<InvalidOperationException>(() => DangerousTestKeyProvider.Default);

            DangerousTestKeyProvider.Enable();

            var provider = DangerousTestKeyProvider.Default;
            provider.ActiveKeyId.Should().Be(1);
            provider.TryGetKey(1).Should().NotBeNull();

            // Still the shared instance, not a fresh one per access.
            DangerousTestKeyProvider.Default.Should().BeSameAs(provider);
        }
        finally
        {
            DangerousTestKeyProvider.Enable();
        }
    }

    [Fact]
    public void Opt_in_probe_fails_closed_on_an_undefined_or_malformed_switch()
    {
        // Deliberately independent of DangerousTestKeyProvider: every name below is freshly
        // generated, so this asserts the AppContext contract the gate rests on and cannot start
        // passing for the wrong reason as the provider's caching behaviour changes.
        // The gate is `TryGetSwitch(...) && enabled`, so it can only open on an explicit true.
        // This pins the platform half of that: a switch nobody defined, and one whose configured
        // value is not a bool, must both read as off rather than defaulting to on.
        var undefined = "Moongazing.OrionVault.Testing.Probe.Undefined." + Guid.NewGuid().ToString("N");
        AppContext.TryGetSwitch(undefined, out var undefinedEnabled).Should().BeFalse();
        undefinedEnabled.Should().BeFalse();

        var malformed = "Moongazing.OrionVault.Testing.Probe.Malformed." + Guid.NewGuid().ToString("N");
        AppDomain.CurrentDomain.SetData(malformed, "yes-please");

        // Guard against a vacuous pass: if SetData did not reach the store TryGetSwitch reads,
        // the assertion below would hold for the wrong reason.
        AppContext.GetData(malformed).Should().Be("yes-please");
        AppContext.TryGetSwitch(malformed, out var malformedEnabled).Should().BeFalse();
        malformedEnabled.Should().BeFalse();
    }

    [Fact]
    public void Zero_key_provider_is_obsolete_under_a_suppressible_diagnostic_id()
    {
        // A consumer must write NoWarn/#pragma for OV9000 to use it, rather than sliding past a
        // generic CS0618 they may already be suppressing wholesale.
        var obsolete = typeof(DangerousTestKeyProvider).GetCustomAttribute<ObsoleteAttribute>();

        obsolete.Should().NotBeNull();
        obsolete!.DiagnosticId.Should().Be("OV9000");
    }

    [Fact]
    public void Testing_package_ships_no_IEncryptor_implementation()
    {
        // A fake encryptor in a package on nuget.org writes plaintext into [Encrypted] columns
        // behind a well-formed envelope. The real encryptor is the only one that ships.
        var encryptors = typeof(DangerousTestKeyProvider).Assembly
            .GetTypes()
            .Where(t => typeof(IEncryptor).IsAssignableFrom(t) && t is { IsInterface: false, IsAbstract: false })
            .Select(t => t.FullName);

        encryptors.Should().BeEmpty();
    }
}
#pragma warning restore OV9000
