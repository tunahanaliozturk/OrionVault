namespace Moongazing.OrionVault.EntityFrameworkCore.IntegrationTests;

using Docker.DotNet;
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
    public const string SkipReason = "Docker did not answer a ping on this machine, so the container-backed tests cannot run.";

    private static readonly Lazy<bool> Available = new(Probe, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>True when the Docker daemon answers a ping. Probed once; the result is cached for the run.</summary>
    public static bool IsAvailable => Available.Value;

    /// <summary>
    /// Asks a daemon to answer a ping, rather than looking for a pipe or a socket file. Existence
    /// checks get this wrong in both directions: a set-but-unreachable <c>DOCKER_HOST</c> - the shape
    /// a CI agent with inherited remote-Docker configuration has - reported "available" and made every
    /// container test RUN and FAIL instead of skipping, and on Windows
    /// <c>Directory.Exists(@"\\.\pipe")</c> is false even with Docker Desktop running (the named-pipe
    /// filesystem only answers an enumeration of <c>\\.\pipe\</c>), which skipped the whole suite on a
    /// machine that could have run it.
    /// <para>
    /// Both candidate endpoints are tried, because that is what Testcontainers does: it walks its
    /// endpoint providers and takes the first one that ANSWERS, so an unreachable <c>DOCKER_HOST</c>
    /// falls back to the platform default rather than failing. Probing only <c>DOCKER_HOST</c> would
    /// skip a machine that can in fact run the suite; probing only the default would report available
    /// on one that cannot. Note <c>new DockerClientConfiguration()</c> does NOT read
    /// <c>DOCKER_HOST</c> - it resolves straight to the local pipe or socket - so the variable has to
    /// be passed explicitly.
    /// </para>
    /// </summary>
    private static bool Probe()
    {
        var configured = Environment.GetEnvironmentVariable("DOCKER_HOST");
        if (!string.IsNullOrWhiteSpace(configured)
            && Uri.TryCreate(configured, UriKind.Absolute, out var endpoint)
            && CanReach(endpoint))
        {
            return true;
        }

        return CanReach(endpoint: null);
    }

    /// <summary>
    /// Whether a Docker daemon answers a ping at <paramref name="endpoint"/>, or at the platform
    /// default when it is <see langword="null"/>. Bounded, so an unreachable endpoint reports quickly
    /// instead of hanging the run.
    /// </summary>
    internal static bool CanReach(Uri? endpoint)
    {
        try
        {
            using var configuration = endpoint is null
                ? new DockerClientConfiguration()
                : new DockerClientConfiguration(endpoint);
            using var client = configuration.CreateClient();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            client.System.PingAsync(timeout.Token).GetAwaiter().GetResult();
            return true;
        }
#pragma warning disable CA1031 // Any failure to reach the daemon means the same thing: not available.
        catch (Exception)
#pragma warning restore CA1031
        {
            return false;
        }
    }
}

/// <summary>
/// The probe's own check. A green container suite means nothing if the thing deciding whether to run
/// it is wrong, and the failure mode this guards is specifically a <c>DOCKER_HOST</c> that is set but
/// unreachable: reporting it "available" makes every container test run and fail instead of skipping.
/// </summary>
public sealed class DockerEnvironmentProbeTests
{
    [Fact]
    public void An_unreachable_endpoint_reports_unavailable_rather_than_throwing()
    {
        // Port 59999 on the loopback: nothing listens, so the connection is refused immediately.
        var unreachable = new Uri("tcp://127.0.0.1:59999");

        var start = DateTimeOffset.UtcNow;
        var reachable = DockerEnvironment.CanReach(unreachable);
        var elapsed = DateTimeOffset.UtcNow - start;

        Assert.False(reachable);
        Assert.True(
            elapsed < TimeSpan.FromSeconds(30),
            $"the probe must be bounded so a stale DOCKER_HOST does not hang the run; took {elapsed}.");
    }
}
