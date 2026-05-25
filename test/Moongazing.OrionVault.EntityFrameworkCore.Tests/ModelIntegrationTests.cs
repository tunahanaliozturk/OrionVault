namespace Moongazing.OrionVault.EntityFrameworkCore.Tests;

using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Moongazing.OrionVault.Abstractions;
using Moongazing.OrionVault.Diagnostics;
using Moongazing.OrionVault.EntityFrameworkCore.Internal;
using Moongazing.OrionVault.Exceptions;
using Moongazing.OrionVault.Internal;
using Xunit;

public class ModelIntegrationTests
{
    private static readonly byte[] Key = new byte[32];
    private static readonly OrionVaultDiagnostics Diag = new();

    private sealed class OneKey : IKeyProvider
    {
        public short ActiveKeyId => 1;
        public ReadOnlyMemory<byte>? TryGetKey(short keyId) => keyId == 1 ? Key : null;
    }

    public class UserAttr
    {
        public Guid Id { get; set; }
        [Encrypted] public string Email { get; set; } = null!;
    }

    public class UserFluent
    {
        public Guid Id { get; set; }
        public string Email { get; set; } = null!;
    }

    public class UserBadType
    {
        public Guid Id { get; set; }
        [Encrypted] public int Number { get; set; }
    }

    private sealed class FluentCtx : DbContext
    {
        public FluentCtx(DbContextOptions opt) : base(opt) { }
        public DbSet<UserFluent> Users => Set<UserFluent>();
        protected override void OnModelCreating(ModelBuilder mb)
            => mb.Entity<UserFluent>().Property(u => u.Email).IsEncrypted();
    }

    private static EncryptionConfigurator CreateConfigurator()
    {
        var enc = new AesGcmEncryptor(new OneKey(), Diag);
        return new EncryptionConfigurator(new EncryptedValueConverterFactory(enc));
    }

    [Fact]
    public void Configurator_attaches_string_converter_for_attribute_marked_property()
    {
        var mb = new ModelBuilder();
        // The parameterless ModelBuilder ctor wires no property-discovery conventions, so
        // properties must be registered explicitly for this lightweight test surface.
        mb.Entity<UserAttr>().Property(u => u.Email);
        CreateConfigurator().Configure(mb);

        var prop = mb.Model.FindEntityType(typeof(UserAttr))!.FindProperty(nameof(UserAttr.Email))!;
        prop.GetValueConverter().Should().BeOfType<EncryptedStringConverter>();
    }

    [Fact]
    public void IsEncrypted_sets_annotation_on_property()
    {
        var opts = new DbContextOptionsBuilder<FluentCtx>().UseSqlite("Data Source=:memory:").Options;
        using var ctx = new FluentCtx(opts);

        var prop = ctx.Model.FindEntityType(typeof(UserFluent))!.FindProperty(nameof(UserFluent.Email))!;
        prop.FindAnnotation("OrionVault:Encrypted")?.Value.Should().Be(true);
    }

    [Fact]
    public void Configurator_throws_when_attribute_on_unsupported_type()
    {
        var mb = new ModelBuilder();
        mb.Entity<UserBadType>().Property(u => u.Number);

        var act = () => CreateConfigurator().Configure(mb);
        act.Should().Throw<OrionVaultConfigurationException>()
            .WithMessage("*Number*");
    }
}
