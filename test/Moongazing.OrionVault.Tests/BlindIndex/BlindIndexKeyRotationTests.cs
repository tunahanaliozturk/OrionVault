namespace Moongazing.OrionVault.Tests.BlindIndex;

using FluentAssertions;
using Moongazing.OrionVault.BlindIndex;
using Xunit;

/// <summary>
/// Exercises the rotation contract: after rotating the active blind index key, values written
/// under the OLD key still match via the retained old version, while NEW writes use the new
/// version. This is the property that lets equality search keep working across a rotation until
/// a re-index sweep migrates rows to the current version.
/// </summary>
public class BlindIndexKeyRotationTests
{
    private static readonly byte[] OldKey = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] NewKey = Enumerable.Range(0, 32).Select(i => (byte)(i ^ 0xFF)).ToArray();

    // Provider BEFORE rotation: only v1 exists and is active.
    private static HmacBlindIndexProvider BeforeRotation()
        => new(new Dictionary<short, byte[]> { [1] = OldKey }, activeVersion: 1);

    // Provider AFTER rotation: v2 is active for new writes, v1 retained so old rows still match.
    private static HmacBlindIndexProvider AfterRotation()
        => new(new Dictionary<short, byte[]> { [1] = OldKey, [2] = NewKey }, activeVersion: 2);

    [Fact]
    public void Old_key_index_still_matches_after_rotation_via_retained_version()
    {
        // Row written under the old key, before rotation.
        var storedUnderOldKey = BeforeRotation().Compute("ali@example.com").Bytes;

        var afterRotation = AfterRotation();

        // The retained v1 key still verifies the old row.
        afterRotation.Matches("ali@example.com", storedUnderOldKey).Should().BeTrue();
    }

    [Fact]
    public void New_writes_use_the_new_active_version_after_rotation()
    {
        var afterRotation = AfterRotation();

        var newWrite = afterRotation.Compute("veli@example.com");

        newWrite.Version.Should().Be(2);
    }

    [Fact]
    public void Search_across_rotation_matches_both_old_and_new_rows()
    {
        // Old row stamped under v1, new row stamped under v2 - both for the SAME plaintext.
        var oldRow = BeforeRotation().Compute("ali@example.com").Bytes;
        var afterRotation = AfterRotation();
        var newRow = afterRotation.Compute("ali@example.com").Bytes;

        oldRow.Should().NotEqual(newRow, "the two key versions yield different MACs");

        // ComputeAllVersions yields one probe per version; a row matches if it equals ANY probe.
        // This is exactly the OR-predicate a caller would push into the database.
        var probes = afterRotation.ComputeAllVersions("ali@example.com")
            .Select(r => r.Bytes)
            .ToList();

        probes.Should().ContainEquivalentOf(oldRow);
        probes.Should().ContainEquivalentOf(newRow);
    }

    [Fact]
    public void Reindex_path_recomputes_an_old_row_under_the_new_active_version()
    {
        // A re-index sweep: detect the stored version, then recompute under the active version.
        var afterRotation = AfterRotation();
        var oldRow = BeforeRotation().Compute("ali@example.com").Bytes;

        BlindIndexResult.TryReadVersion(oldRow, out var storedVersion).Should().BeTrue();
        storedVersion.Should().Be(1);
        storedVersion.Should().NotBe(afterRotation.ActiveVersion, "row is stale and needs re-indexing");

        // The re-indexed value: same plaintext recomputed under the active version.
        var reindexed = afterRotation.Compute("ali@example.com");

        reindexed.Version.Should().Be(afterRotation.ActiveVersion);
        reindexed.Bytes.Should().NotEqual(oldRow);
        // After re-index the row is on the current version and still verifies.
        afterRotation.Matches("ali@example.com", reindexed.Bytes).Should().BeTrue();
    }
}
