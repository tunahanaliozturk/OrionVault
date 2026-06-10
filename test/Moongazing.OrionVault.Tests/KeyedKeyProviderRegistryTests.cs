namespace Moongazing.OrionVault.Tests;

using Microsoft.Extensions.DependencyInjection;
using Moongazing.OrionVault;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.DependencyInjection;
using Moongazing.OrionVault.Internal;
using Xunit;

public sealed class KeyedKeyProviderRegistryTests
{
    private sealed class StubProvider : IKeyProvider
    {
        public StubProvider(short activeKeyId) { ActiveKeyId = activeKeyId; }
        public short ActiveKeyId { get; }
        public ReadOnlyMemory<byte>? TryGetKey(short keyId) => null;
    }

    [Fact]
    public void Register_returns_true_on_first_call_false_on_subsequent_calls()
    {
        var registry = new KeyedKeyProviderRegistry();
        Assert.True(registry.Register("primary", new StubProvider(1)));
        Assert.False(registry.Register("primary", new StubProvider(2)));
    }

    [Fact]
    public void GetProvider_returns_registered_provider()
    {
        var registry = new KeyedKeyProviderRegistry();
        var p = new StubProvider(7);
        registry.Register("primary", p);

        var resolved = registry.GetProvider("primary");

        Assert.Same(p, resolved);
    }

    [Fact]
    public void GetProvider_throws_for_unknown_name()
    {
        var registry = new KeyedKeyProviderRegistry();

        var ex = Assert.Throws<KeyNotFoundException>(() => registry.GetProvider("ghost"));
        Assert.Contains("'ghost'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TryGetProvider_returns_true_for_registered_name()
    {
        var registry = new KeyedKeyProviderRegistry();
        var p = new StubProvider(1);
        registry.Register("primary", p);

        Assert.True(registry.TryGetProvider("primary", out var resolved));
        Assert.Same(p, resolved);
    }

    [Fact]
    public void TryGetProvider_returns_false_for_unknown_name()
    {
        var registry = new KeyedKeyProviderRegistry();

        Assert.False(registry.TryGetProvider("ghost", out var resolved));
        Assert.Null(resolved);
    }

    [Fact]
    public void RegisteredNames_preserves_registration_order()
    {
        var registry = new KeyedKeyProviderRegistry();
        registry.Register("primary", new StubProvider(1));
        registry.Register("audit", new StubProvider(2));
        registry.Register("staging", new StubProvider(3));

        var names = registry.RegisteredNames();

        Assert.Equal(new[] { "primary", "audit", "staging" }, names);
    }

    [Fact]
    public void IsRegistered_toggles_after_Register()
    {
        var registry = new KeyedKeyProviderRegistry();
        Assert.False(registry.IsRegistered("primary"));
        registry.Register("primary", new StubProvider(1));
        Assert.True(registry.IsRegistered("primary"));
    }

    [Fact]
    public void Register_rejects_null_arguments()
    {
        var registry = new KeyedKeyProviderRegistry();
        Assert.Throws<ArgumentException>(() => registry.Register(string.Empty, new StubProvider(1)));
        Assert.Throws<ArgumentNullException>(() => registry.Register("name", null!));
    }

    [Fact]
    public void AddNamedKeyProvider_with_instance_registers_into_registry()
    {
        var services = new ServiceCollection();
        var builder = services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
            o.ActiveKeyId = 1;
        });
        builder.AddNamedKeyProvider("audit", new StubProvider(9));

        using var sp = services.BuildServiceProvider();
        var registry = sp.GetRequiredService<IKeyedKeyProviderRegistry>();

        Assert.True(registry.IsRegistered("audit"));
        Assert.Equal(9, registry.GetProvider("audit").ActiveKeyId);
    }

    [Fact]
    public void AddNamedKeyProvider_with_factory_resolves_via_service_provider()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new StubProvider(11));
        var builder = services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
            o.ActiveKeyId = 1;
        });
        builder.AddNamedKeyProvider("primary", sp => sp.GetRequiredService<StubProvider>());

        using var serviceProvider = services.BuildServiceProvider();
        var registry = serviceProvider.GetRequiredService<IKeyedKeyProviderRegistry>();

        Assert.Equal(11, registry.GetProvider("primary").ActiveKeyId);
    }

    [Fact]
    public void AddNamedKeyProvider_multiple_calls_populate_in_order()
    {
        var services = new ServiceCollection();
        var builder = services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
            o.ActiveKeyId = 1;
        });
        builder
            .AddNamedKeyProvider("primary", new StubProvider(1))
            .AddNamedKeyProvider("audit", new StubProvider(2))
            .AddNamedKeyProvider("staging", new StubProvider(3));

        using var sp = services.BuildServiceProvider();
        var registry = sp.GetRequiredService<IKeyedKeyProviderRegistry>();

        Assert.Equal(new[] { "primary", "audit", "staging" }, registry.RegisteredNames());
    }

    [Fact]
    public void AddNamedKeyProvider_rejects_invalid_arguments()
    {
        var services = new ServiceCollection();
        var builder = services.AddOrionVault(o =>
        {
            o.UseStaticKeys(k => k.Add(1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
            o.ActiveKeyId = 1;
        });

        Assert.Throws<ArgumentNullException>(() => builder.AddNamedKeyProvider(null!, new StubProvider(1)));
        Assert.Throws<ArgumentException>(() => builder.AddNamedKeyProvider(string.Empty, new StubProvider(1)));
        Assert.Throws<ArgumentNullException>(() => builder.AddNamedKeyProvider("name", (IKeyProvider)null!));
        Assert.Throws<ArgumentNullException>(() => builder.AddNamedKeyProvider("name", (Func<IServiceProvider, IKeyProvider>)null!));
    }
}
