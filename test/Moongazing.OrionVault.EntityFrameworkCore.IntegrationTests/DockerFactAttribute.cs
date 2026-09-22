namespace Moongazing.OrionVault.EntityFrameworkCore.IntegrationTests;

using System.Runtime.InteropServices;
using Xunit;

/// <summary>
/// A <see cref="FactAttribute"/> for a test that needs a container. Without a reachable Docker daemon
/// the test is skipped instead of failing: a machine with no Docker cannot say anything about the
/// code, and a wall of red tests hides the ones that mean something.
/// </summary>
/// <remarks>Same shape as the sibling OrionLock repo's probe, so the family's suites stay honest the same way.</remarks>
public sealed class DockerFactAttribute : FactAttribute
{
    /// <inheritdoc cref="DockerFactAttribute"/>
    public DockerFactAttribute()
    {
        if (!DockerEnvironment.IsAvailable)
        {
            Skip = DockerEnvironment.SkipReason;
        }
    }
}

/// <summary>The images the container-backed suites run against, pinned in one place.</summary>
public static class ContainerImages
{
    /// <summary>SQL Server: the length-ENFORCING store in the truncate-versus-error question.</summary>
    public const string SqlServer = "mcr.microsoft.com/mssql/server:2022-latest";

    /// <summary>MySQL: the store that can be put into a non-strict mode and truncate instead.</summary>
    public const string MySql = "mysql:8.4";
}

/// <summary>Whether this machine can start containers, decided once per test run.</summary>
public static class DockerEnvironment
{
    /// <summary>Shown on every skipped test, so a green run still says why it was cheap.</summary>
    public const string SkipReason = "Docker is not reachable on this machine, so the container-backed tests cannot run.";

    private static readonly Lazy<bool> Available = new(Probe, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>True when a Docker endpoint answers. Probed once; the result is cached for the run.</summary>
    public static bool IsAvailable => Available.Value;

    // Probed by existence, not by an API call: opening the pipe or socket is enough to tell a machine
    // without Docker from one with it, and it costs no daemon round trip. DOCKER_HOST wins when it is
    // set, because that is what Testcontainers itself honours first.
    private static bool Probe()
    {
        var configured = Environment.GetEnvironmentVariable("DOCKER_HOST");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return true;
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            try
            {
                // The trailing separator matters: the named-pipe filesystem answers an enumeration of
                // "\\.\pipe\" but Directory.Exists(@"\\.\pipe") is false, which would skip the whole
                // suite on a machine that does have Docker Desktop running.
                return Directory.EnumerateFiles(@"\\.\pipe\").Any(static pipe =>
                    pipe.Contains("docker_engine", StringComparison.OrdinalIgnoreCase)
                    || pipe.Contains("dockerDesktopLinuxEngine", StringComparison.OrdinalIgnoreCase));
            }
            catch (IOException)
            {
                return false;
            }
        }

        return File.Exists("/var/run/docker.sock");
    }
}
