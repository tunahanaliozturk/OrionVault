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
