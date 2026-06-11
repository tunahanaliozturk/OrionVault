namespace Moongazing.OrionVault.Tests;

using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Rotation;
using Xunit;

public sealed class KeyRotationObserverTests
{
    [Fact]
    public void NullKeyRotationObserver_OnRotationCycleCompleted_is_a_noop()
    {
        var sut = new NullKeyRotationObserver();

        sut.OnRotationCycleCompleted(new RotationCycleResult(Scanned: 10, Rotated: 5, Skipped: 3, Errors: 2));
    }

    [Fact]
    public void Custom_observer_receives_the_RotationCycleResult_intact()
    {
        RotationCycleResult? captured = null;
        var sut = new CapturingObserver(r => captured = r);

        var input = new RotationCycleResult(Scanned: 100, Rotated: 75, Skipped: 20, Errors: 5);
        sut.OnRotationCycleCompleted(input);

        Assert.NotNull(captured);
        Assert.Equal(100, captured!.Scanned);
        Assert.Equal(75, captured.Rotated);
        Assert.Equal(20, captured.Skipped);
        Assert.Equal(5, captured.Errors);
    }

    private sealed class CapturingObserver : IKeyRotationObserver
    {
        private readonly System.Action<RotationCycleResult> capture;
        public CapturingObserver(System.Action<RotationCycleResult> capture) => this.capture = capture;
        public void OnRotationCycleCompleted(RotationCycleResult result) => capture(result);
    }
}
