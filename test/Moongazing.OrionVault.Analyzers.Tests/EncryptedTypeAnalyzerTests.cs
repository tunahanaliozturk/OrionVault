namespace Moongazing.OrionVault.Analyzers.Tests;

using Xunit;
using Verify = Microsoft.CodeAnalysis.CSharp.Testing.CSharpAnalyzerVerifier<
    Moongazing.OrionVault.Analyzers.EncryptedTypeAnalyzer,
    Microsoft.CodeAnalysis.Testing.DefaultVerifier>;

public class EncryptedTypeAnalyzerTests
{
    [Fact]
    public async Task OV0001_fires_when_Encrypted_on_int_property()
    {
        var src = """
            namespace Moongazing.OrionVault.EntityFrameworkCore {
                public sealed class EncryptedAttribute : System.Attribute { }
            }
            namespace Demo {
                using Moongazing.OrionVault.EntityFrameworkCore;
                public class User {
                    [Encrypted] public int {|OV0001:Number|} { get; set; }
                }
            }
            """;
        await Verify.VerifyAnalyzerAsync(src);
    }

    [Fact]
    public async Task OV0001_does_not_fire_for_string_property()
    {
        var src = """
            namespace Moongazing.OrionVault.EntityFrameworkCore {
                public sealed class EncryptedAttribute : System.Attribute { }
            }
            namespace Demo {
                using Moongazing.OrionVault.EntityFrameworkCore;
                public class User {
                    [Encrypted] public string Email { get; set; } = null!;
                }
            }
            """;
        await Verify.VerifyAnalyzerAsync(src);
    }

    [Fact]
    public async Task OV0001_does_not_fire_for_byte_array_property()
    {
        var src = """
            namespace Moongazing.OrionVault.EntityFrameworkCore {
                public sealed class EncryptedAttribute : System.Attribute { }
            }
            namespace Demo {
                using Moongazing.OrionVault.EntityFrameworkCore;
                public class User {
                    [Encrypted] public byte[] Scan { get; set; } = null!;
                }
            }
            """;
        await Verify.VerifyAnalyzerAsync(src);
    }
}
