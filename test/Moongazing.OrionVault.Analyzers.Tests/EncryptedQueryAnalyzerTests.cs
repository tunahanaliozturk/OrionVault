namespace Moongazing.OrionVault.Analyzers.Tests;

using Microsoft.CodeAnalysis;
using Xunit;
using Verify = Microsoft.CodeAnalysis.CSharp.Testing.CSharpAnalyzerVerifier<
    Moongazing.OrionVault.Analyzers.EncryptedQueryAnalyzer,
    Microsoft.CodeAnalysis.Testing.DefaultVerifier>;

public class EncryptedQueryAnalyzerTests
{
    // Stubs stand in for the real EF Core surface so the analyzer tests stay a compile-only
    // fixture: the analyzer matches on System.Linq.Queryable plus the shape of the lambda body,
    // not on EF's own types.
    private const string Preamble = """
        using System.Linq;
        using System.Collections.Generic;
        namespace Moongazing.OrionVault.EntityFrameworkCore {
            public sealed class EncryptedAttribute : System.Attribute { }
        }
        namespace Microsoft.EntityFrameworkCore {
            public sealed class DbFunctions { }
            public static class EF { public static DbFunctions Functions => null!; }
            public static class DbFunctionsExtensions {
                public static bool Like(this DbFunctions _, string matchExpression, string pattern) => false;
            }
            public static class RelationalQueryableExtensions {
                public static int ExecuteDelete<T>(this IQueryable<T> source) => 0;
            }
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

    private static string Query(string body) => Preamble + $$"""
        namespace Demo {
            using Microsoft.EntityFrameworkCore;
            public static class Q {
                public static object Find() {{body}}
            }
        }
        """;

    [Fact]
    public async Task OV0002_fires_when_Where_compares_encrypted_property_to_literal()
    {
        await Verify.VerifyAnalyzerAsync(Query("""=> Db.Users.Where(u => {|OV0002:u.Email == "a@b.com"|}).ToList();"""));
    }

    [Fact]
    public async Task OV0002_does_not_fire_for_unencrypted_property()
    {
        await Verify.VerifyAnalyzerAsync(Query("""=> Db.Users.Where(u => u.Name == "Ali").ToList();"""));
    }

    [Fact]
    public async Task OV0003_fires_for_OrderBy_on_encrypted_property()
    {
        await Verify.VerifyAnalyzerAsync(Query("=> Db.Users.OrderBy(u => {|OV0003:u.Email|}).ToList();"));
    }

    // --- Regression: the shapes people actually write. Every one of these is an invocation, so
    // none of them was flagged while the analyzer matched IBinaryOperation only. ---

    [Fact]
    public void OV0002_is_an_error_rather_than_a_warning()
    {
        // The diagnostic describes a predicate that is false for every row; a consumer without
        // TreatWarningsAsErrors would otherwise ship it.
        Assert.Equal(DiagnosticSeverity.Error, EncryptedQueryAnalyzer.WhereRule.DefaultSeverity);
    }

    [Fact]
    public async Task OV0002_fires_for_Contains_on_encrypted_property()
    {
        await Verify.VerifyAnalyzerAsync(Query("""=> Db.Users.Where(u => {|OV0002:u.Email.Contains("@acme.com")|}).ToList();"""));
    }

    [Fact]
    public async Task OV0002_fires_for_StartsWith_on_encrypted_property()
    {
        await Verify.VerifyAnalyzerAsync(Query("""=> Db.Users.Where(u => {|OV0002:u.Email.StartsWith("a")|}).ToList();"""));
    }

    [Fact]
    public async Task OV0002_fires_for_static_string_Equals_on_encrypted_property()
    {
        await Verify.VerifyAnalyzerAsync(Query("""=> Db.Users.Where(u => {|OV0002:string.Equals(u.Email, "a@b.com")|}).ToList();"""));
    }

    [Fact]
    public async Task OV0002_fires_for_EF_Functions_Like_on_encrypted_property()
    {
        await Verify.VerifyAnalyzerAsync(Query("""=> Db.Users.Where(u => {|OV0002:EF.Functions.Like(u.Email, "%acme%")|}).ToList();"""));
    }

    [Fact]
    public async Task OV0002_fires_when_a_collection_Contains_the_encrypted_property()
    {
        await Verify.VerifyAnalyzerAsync(Query("""
            {
                    var emails = new List<string>();
                    return Db.Users.Where(u => {|OV0002:emails.Contains(u.Email)|}).ToList();
                }
            """));
    }

    [Fact]
    public async Task OV0002_fires_for_the_predicate_behind_an_ExecuteDelete()
    {
        // ExecuteDelete carries no predicate of its own - its filter is the preceding Where, which
        // is exactly the call the invocation matching now covers. A GDPR erasure written this way
        // deletes nothing and reports success.
        await Verify.VerifyAnalyzerAsync(Query("""=> Db.Users.Where(u => {|OV0002:u.Email.Contains("@acme.com")|}).ExecuteDelete();"""));
    }

    // --- Regression: shapes that must stay quiet, because Error severity makes a false positive
    // a broken build. ---

    [Fact]
    public async Task OV0002_does_not_fire_for_a_null_check_on_an_encrypted_property()
    {
        // `column == null` translates to IS NULL, which is evaluated on the column rather than on
        // its contents, so it works correctly against ciphertext.
        await Verify.VerifyAnalyzerAsync(Query("=> Db.Users.Where(u => u.Email == null).ToList();"));
    }

    [Fact]
    public async Task OV0002_does_not_fire_for_static_string_Equals_against_null()
    {
        // Same null test as `col == null`, reached through a call instead of an operator. The
        // provider translates it to IS NULL either way.
        await Verify.VerifyAnalyzerAsync(Query("=> Db.Users.Where(u => string.Equals(u.Email, null)).ToList();"));
    }

    [Fact]
    public async Task OV0002_does_not_fire_for_object_Equals_against_null()
    {
        await Verify.VerifyAnalyzerAsync(Query("=> Db.Users.Where(u => object.Equals(u.Email, null)).ToList();"));
    }

    [Fact]
    public async Task OV0002_does_not_fire_for_instance_Equals_against_null()
    {
        // The encrypted column is the receiver here rather than an argument, so this also pins
        // that the exemption is keyed on the operands and not on their position.
        await Verify.VerifyAnalyzerAsync(Query("=> Db.Users.Where(u => u.Email.Equals(null)).ToList();"));
    }

    [Fact]
    public async Task OV0002_does_not_fire_for_ReferenceEquals_against_null()
    {
        await Verify.VerifyAnalyzerAsync(Query("=> Db.Users.Where(u => object.ReferenceEquals(u.Email, null)).ToList();"));
    }

    // `u.Email is null` is not a sibling shape to guard: C# rejects an `is` pattern inside an
    // expression tree (CS8122), so it cannot reach an IQueryable predicate in the first place.

    [Fact]
    public async Task OV0002_does_not_fire_for_in_memory_LINQ_over_decrypted_values()
    {
        // Once the rows are materialised the value converter has already decrypted Email, so the
        // comparison is over plaintext and is correct.
        await Verify.VerifyAnalyzerAsync(Query("""
            {
                    var loaded = Db.Users.ToList();
                    return loaded.Where(u => u.Email == "a@b.com").ToList();
                }
            """));
    }

    [Fact]
    public async Task OV0002_does_not_fire_for_an_invocation_on_an_unencrypted_property()
    {
        await Verify.VerifyAnalyzerAsync(Query("""=> Db.Users.Where(u => u.Name.Contains("Ali")).ToList();"""));
    }
}
