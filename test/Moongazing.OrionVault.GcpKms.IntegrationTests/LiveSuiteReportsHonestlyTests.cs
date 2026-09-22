namespace Moongazing.OrionVault.GcpKms.IntegrationTests;

using System.Reflection;
using Xunit;

/// <summary>
/// Guards the reporting contract of the live suite rather than Cloud KMS itself. A suite that
/// returns early when its credentials are absent reports green while asserting nothing, and a green
/// suite that proves nothing is worse than a red one because it is trusted.
/// </summary>
public sealed class LiveSuiteReportsHonestlyTests
{
    [Fact]
    public void Live_facts_are_skipped_rather_than_vacuously_passed_when_unconfigured()
    {
        var facts = typeof(GcpKmsKeyProviderLiveTests)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(m => m.GetCustomAttribute<FactAttribute>())
            .Where(a => a is not null)
            .ToList();

        Assert.NotEmpty(facts);

        // Skipped exactly when the suite cannot run: green only ever means the live assertions ran.
        Assert.All(facts, a => Assert.Equal(
            !GcpKmsKeyProviderLiveTests.IsConfigured,
            a!.Skip is not null));
    }
}
