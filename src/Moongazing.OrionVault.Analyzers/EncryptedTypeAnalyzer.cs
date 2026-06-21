namespace Moongazing.OrionVault.Analyzers;

using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class EncryptedTypeAnalyzer : DiagnosticAnalyzer
{
    public static readonly DiagnosticDescriptor Rule = new(
        id: "OV0001",
        title: "[Encrypted] needs string or byte[] storage",
        messageFormat: "[Encrypted] encrypts string or byte[] storage. Property '{0}' has type '{1}'; "
            + "this is supported only when EF Core maps it through a value converter to string or byte[] "
            + "(for example a value object), otherwise model building fails.",
        category: "Moongazing.OrionVault",
        defaultSeverity: DiagnosticSeverity.Info,
        isEnabledByDefault: true,
        description: "OrionVault's [Encrypted] attribute encrypts string or byte[] storage. A property of "
            + "another type is supported only when EF Core maps it through a value converter to string or "
            + "byte[]; without such a converter, model building throws. The severity is informational "
            + "because the analyzer cannot see EF Core value converters at compile time.");

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
