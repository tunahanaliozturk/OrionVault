namespace Moongazing.OrionVault.Tests;

using Moongazing.OrionVault.Rotation;
using Xunit;

public sealed class ReencryptionReportTests
{
    [Fact]
    public void Empty_is_all_zero()
    {
        var e = ReencryptionReport.Empty;
        Assert.Equal(0, e.Scanned);
        Assert.Equal(0, e.ReEncrypted);
        Assert.Equal(0, e.ReIndexed);
        Assert.Equal(0, e.Skipped);
        Assert.Equal(0, e.Errors);
    }

    [Fact]
    public void Add_sums_each_counter_componentwise()
    {
        var a = new ReencryptionReport(10, 4, 3, 2, 1);
        var b = new ReencryptionReport(5, 1, 1, 2, 1);

        var sum = a.Add(b);

        Assert.Equal(15, sum.Scanned);
        Assert.Equal(5, sum.ReEncrypted);
        Assert.Equal(4, sum.ReIndexed);
        Assert.Equal(4, sum.Skipped);
        Assert.Equal(2, sum.Errors);
    }

    [Fact]
    public void Add_with_Empty_is_identity()
    {
        var a = new ReencryptionReport(7, 3, 2, 1, 1);
        Assert.Equal(a, a.Add(ReencryptionReport.Empty));
        Assert.Equal(a, ReencryptionReport.Empty.Add(a));
    }

    [Fact]
    public void Add_null_throws()
    {
        var a = ReencryptionReport.Empty;
        Assert.Throws<ArgumentNullException>(() => a.Add(null!));
    }
}
