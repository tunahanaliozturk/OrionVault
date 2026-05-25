namespace Moongazing.OrionVault.Analyzers;

using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class EncryptedTypeAnalyzer : DiagnosticAnalyzer
{
    public static readonly DiagnosticDescriptor Rule = new(
        id: "OV0001",
        title: "[Encrypted] only supports string or byte[]",
        messageFormat: "[Encrypted] only supports string or byte[] properties. Property '{0}' has type '{1}'.",
        category: "Moongazing.OrionVault",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "OrionVault's [Encrypted] attribute is valid only on properties of type string or byte[].");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSymbolAction(AnalyzeProperty, SymbolKind.Property);
    }

    private static void AnalyzeProperty(SymbolAnalysisContext ctx)
    {
        var prop = (IPropertySymbol)ctx.Symbol;
        if (!EncryptedSymbolHelper.HasEncryptedAttribute(prop)) return;

        var t = prop.Type;
        var isString = t.SpecialType == SpecialType.System_String;
        var isByteArray = t is IArrayTypeSymbol arr && arr.ElementType.SpecialType == SpecialType.System_Byte;
        if (isString || isByteArray) return;

        ctx.ReportDiagnostic(Diagnostic.Create(
            Rule, prop.Locations[0], prop.Name, t.ToDisplayString()));
    }
}
