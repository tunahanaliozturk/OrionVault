namespace Moongazing.OrionVault.Analyzers.Tests;

using Xunit;
using Verify = Microsoft.CodeAnalysis.CSharp.Testing.CSharpAnalyzerVerifier<
    Moongazing.OrionVault.Analyzers.EncryptedQueryAnalyzer,
    Microsoft.CodeAnalysis.Testing.DefaultVerifier>;

public class EncryptedQueryAnalyzerTests
{
    private const string Preamble = """
        using System.Linq;
        namespace Moongazing.OrionVault.EntityFrameworkCore {
            public sealed class EncryptedAttribute : System.Attribute { }
        }
        namespace Demo {
            using Moongazing.OrionVault.EntityFrameworkCore;
            public class User {
                public int Id { get; set; }
                [Encrypted] public string Email { get; set; } = "";
                public string Name { get; set; } = "";
            }
            public static class Db {
                public static IQueryable<User> Users => null!;
            }
        }
        """;

    [Fact]
    public async Task OV0002_fires_when_Where_compares_encrypted_property_to_literal()
    {
        var src = Preamble + """
            namespace Demo {
                public static class Q {
                    public static System.Collections.Generic.IEnumerable<User> Find() =>
                        Db.Users.Where(u => {|OV0002:u.Email == "a@b.com"|}).ToList();
                }
            }
            """;
        await Verify.VerifyAnalyzerAsync(src);
    }

    [Fact]
    public async Task OV0002_does_not_fire_for_unencrypted_property()
    {
        var src = Preamble + """
            namespace Demo {
                public static class Q {
                    public static System.Collections.Generic.IEnumerable<User> Find() =>
                        Db.Users.Where(u => u.Name == "Ali").ToList();
                }
            }
            """;
        await Verify.VerifyAnalyzerAsync(src);
    }

    [Fact]
    public async Task OV0003_fires_for_OrderBy_on_encrypted_property()
    {
        var src = Preamble + """
            namespace Demo {
                public static class Q {
                    public static System.Collections.Generic.IEnumerable<User> Find() =>
                        Db.Users.OrderBy(u => {|OV0003:u.Email|}).ToList();
                }
            }
            """;
        await Verify.VerifyAnalyzerAsync(src);
    }
}
