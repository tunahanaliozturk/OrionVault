namespace Moongazing.OrionVault.Tests.BlindIndex;

using System.Security.Cryptography;
using FluentAssertions;
using Moongazing.OrionVault.BlindIndex;
using Moongazing.OrionVault.Exceptions;
using Xunit;

public class HmacBlindIndexProviderTests
{
    private static readonly byte[] KeyV1 = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] KeyV2 = Enumerable.Range(0, 32).Select(i => (byte)(i + 100)).ToArray();

    private static HmacBlindIndexProvider OneKey(short active = 1)
        => new(new Dictionary<short, byte[]> { [active] = KeyV1 }, active);

    private static HmacBlindIndexProvider TwoKeys(short active)
        => new(new Dictionary<short, byte[]> { [1] = KeyV1, [2] = KeyV2 }, active);

    [Fact]
    public void Equal_plaintexts_produce_equal_blind_indexes()
    {
        var sut = OneKey();

        var a = sut.Compute("ali@example.com");
        var b = sut.Compute("ali@example.com");

        a.Bytes.Should().Equal(b.Bytes);
        a.Should().Be(b);
        a.Bytes.Length.Should().Be(BlindIndexResult.TotalSize);
    }

    [Fact]
    public void Unequal_plaintexts_produce_unequal_blind_indexes()
    {
        var sut = OneKey();

        var a = sut.Compute("ali@example.com");
        var b = sut.Compute("veli@example.com");

        a.Bytes.Should().NotEqual(b.Bytes);
    }

    [Fact]
    public void Normalization_makes_case_and_whitespace_variants_match_by_default()
    {
        var sut = OneKey();

        var canonical = sut.Compute("ali@example.com");

        sut.Compute("ALI@example.com").Bytes.Should().Equal(canonical.Bytes);
        sut.Compute("  Ali@Example.com  ").Bytes.Should().Equal(canonical.Bytes);
    }

    [Fact]
    public void Normalization_None_preserves_case_sensitivity()
    {
        var sut = new HmacBlindIndexProvider(
            new Dictionary<short, byte[]> { [1] = KeyV1 }, 1, BlindIndexNormalization.None);

        sut.Compute("Value").Bytes.Should().NotEqual(sut.Compute("value").Bytes);
    }

    [Fact]
    public void Blind_index_is_stable_across_separate_provider_instances_with_same_key()
    {
        // Two independently constructed providers (simulating two processes / hosts) configured
        // with the same key must produce byte-identical indexes, otherwise distributed search
        // would miss.
        var instanceA = OneKey();
        var instanceB = OneKey();

        instanceA.Compute("ali@example.com").Bytes
            .Should().Equal(instanceB.Compute("ali@example.com").Bytes);
    }

    [Fact]
    public void Compute_uses_ActiveVersion_and_stamps_it_into_the_index()
    {
        var sut = TwoKeys(active: 2);

        var result = sut.Compute("x");

        result.Version.Should().Be(2);
        BlindIndexResult.TryReadVersion(result.Bytes, out var v).Should().BeTrue();
        v.Should().Be(2);
    }

    [Fact]
    public void Different_versions_produce_different_indexes_for_same_value()
    {
        var sut = TwoKeys(active: 2);

        var underV1 = sut.ComputeForVersion("ali@example.com", 1);
        var underV2 = sut.ComputeForVersion("ali@example.com", 2);

        underV1.Bytes.Should().NotEqual(underV2.Bytes);
        underV1.Mac.ToArray().Should().NotEqual(underV2.Mac.ToArray());
    }

    [Fact]
    public void ComputeForVersion_throws_for_unknown_version()
    {
        var sut = OneKey();

        var act = () => sut.ComputeForVersion("x", 99);

        act.Should().Throw<OrionVaultKeyNotFoundException>().Which.KeyId.Should().Be(99);
    }

    [Fact]
    public void ComputeAllVersions_returns_one_index_per_version_newest_first()
    {
        var sut = TwoKeys(active: 2);

        var all = sut.ComputeAllVersions("ali@example.com");

        all.Should().HaveCount(2);
        all[0].Version.Should().Be(2); // newest first
        all[1].Version.Should().Be(1);
        // The active-version index must match the one Compute would produce.
        all[0].Bytes.Should().Equal(sut.Compute("ali@example.com").Bytes);
    }

    [Fact]
    public void Matches_resolves_version_from_stored_index_and_verifies()
    {
        var sut = TwoKeys(active: 2);
        var storedUnderV1 = sut.ComputeForVersion("ali@example.com", 1).Bytes;

        sut.Matches("ali@example.com", storedUnderV1).Should().BeTrue();
        sut.Matches("ALI@example.com", storedUnderV1).Should().BeTrue(); // normalization applies
        sut.Matches("veli@example.com", storedUnderV1).Should().BeFalse();
    }

    [Fact]
    public void Matches_returns_false_for_malformed_or_unknown_version_index()
    {
        var sut = OneKey();

        sut.Matches("x", []).Should().BeFalse();
        sut.Matches("x", new byte[BlindIndexResult.TotalSize - 1]).Should().BeFalse();

        // Well-formed length but a version that is not registered.
        var unknownVersion = new byte[BlindIndexResult.TotalSize];
        unknownVersion[0] = 0x7F;
        unknownVersion[1] = 0x7F;
        sut.Matches("x", unknownVersion).Should().BeFalse();
    }

    [Fact]
    public void Matches_is_consistent_with_HMACSHA256_HashData()
    {
        // Pin the algorithm: an index must equal a raw HMAC-SHA256 of the normalized UTF-8 bytes
        // so the format is reproducible outside the library (e.g. in a SQL-side migration tool).
        var sut = OneKey();
        var expectedMac = HMACSHA256.HashData(
            KeyV1, System.Text.Encoding.UTF8.GetBytes("ali@example.com"));

        var result = sut.Compute("ali@example.com");

        result.Mac.ToArray().Should().Equal(expectedMac);
    }

    [Fact]
    public void Ctor_throws_when_active_version_not_registered()
    {
        var act = () => new HmacBlindIndexProvider(new Dictionary<short, byte[]> { [1] = KeyV1 }, 99);

        act.Should().Throw<OrionVaultConfigurationException>().WithMessage("*99*");
    }

    [Fact]
    public void Ctor_throws_when_no_keys_supplied()
    {
        var act = () => new HmacBlindIndexProvider(new Dictionary<short, byte[]>(), 1);

        act.Should().Throw<OrionVaultConfigurationException>();
    }

    [Fact]
    public void Ctor_defensively_copies_keys_so_later_mutation_does_not_change_output()
    {
        var mutable = new byte[32];
        Array.Fill(mutable, (byte)7);
        var sut = new HmacBlindIndexProvider(new Dictionary<short, byte[]> { [1] = mutable }, 1);

        var before = sut.Compute("x").Bytes;
        Array.Fill(mutable, (byte)9); // mutate the source after construction
        var after = sut.Compute("x").Bytes;

        after.Should().Equal(before);
    }

    [Fact]
    public void Compute_throws_on_null_value()
    {
        var sut = OneKey();

        var act = () => sut.Compute(null!);

        act.Should().Throw<ArgumentNullException>();
    }
}
