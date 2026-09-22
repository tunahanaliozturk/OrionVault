using Xunit;

// The zero-key opt-in is an AppContext switch, which is process-global: the test that asserts the
// provider refuses to construct has to turn it off briefly, and a parallel class would see that.
// This assembly is small enough that serial execution costs nothing.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
