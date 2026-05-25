namespace Moongazing.OrionVault.Analyzers;

using System.Collections.Generic;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class EncryptedQueryAnalyzer : DiagnosticAnalyzer
{
    public static readonly DiagnosticDescriptor WhereRule = new(
        id: "OV0002",
        title: "Comparing encrypted column in LINQ always returns false",
        messageFormat: "Comparing encrypted column '{0}' to a value in a LINQ query always returns false (random ciphertext per row). Use a separate HMAC index column for searchable encrypted values, or fetch and filter in memory.",
        category: "Moongazing.OrionVault",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true);

    public static readonly DiagnosticDescriptor OrderRule = new(
        id: "OV0003",
        title: "OrderBy/GroupBy on encrypted column executes client-side",
        messageFormat: "Ordering or grouping by encrypted column '{0}' executes client-side after decryption; large result sets will be slow.",
        category: "Moongazing.OrionVault",
        defaultSeverity: DiagnosticSeverity.Info,
        isEnabledByDefault: true);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(WhereRule, OrderRule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterOperationAction(AnalyzeInvocation, OperationKind.Invocation);
    }

    private static readonly string[] WhereMethods = { "Where", "First", "FirstOrDefault", "Single", "SingleOrDefault", "Any", "Count" };
    private static readonly string[] OrderMethods = { "OrderBy", "OrderByDescending", "ThenBy", "ThenByDescending", "GroupBy" };

    private static void AnalyzeInvocation(OperationAnalysisContext ctx)
    {
        var invocation = (IInvocationOperation)ctx.Operation;
        var method = invocation.TargetMethod;
        if (method.ContainingType?.ToDisplayString() != "System.Linq.Queryable" &&
            method.ContainingType?.ToDisplayString() != "System.Linq.Enumerable")
            return;

        if (System.Array.IndexOf(OrderMethods, method.Name) >= 0)
        {
            ScanLambdaForEncryptedMember(invocation, ctx, OrderRule);
            return;
        }
        if (System.Array.IndexOf(WhereMethods, method.Name) >= 0)
        {
            ScanPredicateForComparison(invocation, ctx);
        }
    }

    private static void ScanLambdaForEncryptedMember(
        IInvocationOperation invocation, OperationAnalysisContext ctx, DiagnosticDescriptor rule)
    {
        foreach (var arg in invocation.Arguments)
        {
            var anon = ExtractAnonymousFunction(arg.Value);
            if (anon is null) continue;
            foreach (var prop in CollectEncryptedMembers(anon))
                ctx.ReportDiagnostic(Diagnostic.Create(rule, prop.Syntax.GetLocation(), prop.Property.Name));
        }
    }

    private static void ScanPredicateForComparison(
        IInvocationOperation invocation, OperationAnalysisContext ctx)
    {
        foreach (var arg in invocation.Arguments)
        {
            var anon = ExtractAnonymousFunction(arg.Value);
            if (anon is null) continue;

            foreach (var op in DescendantsOf(anon))
            {
                if (op is not IBinaryOperation bin) continue;
                if (bin.OperatorKind is not (BinaryOperatorKind.Equals or BinaryOperatorKind.NotEquals)) continue;

                var lhs = UnwrapConversion(bin.LeftOperand) as IPropertyReferenceOperation;
                var rhs = UnwrapConversion(bin.RightOperand) as IPropertyReferenceOperation;
                if (lhs is not null && EncryptedSymbolHelper.HasEncryptedAttribute(lhs.Property))
                    ctx.ReportDiagnostic(Diagnostic.Create(WhereRule, bin.Syntax.GetLocation(), lhs.Property.Name));
                else if (rhs is not null && EncryptedSymbolHelper.HasEncryptedAttribute(rhs.Property))
                    ctx.ReportDiagnostic(Diagnostic.Create(WhereRule, bin.Syntax.GetLocation(), rhs.Property.Name));
            }
        }
    }

    private static IAnonymousFunctionOperation? ExtractAnonymousFunction(IOperation op)
    {
        // Peel conversions (e.g., Func -> Expression<Func>) and DelegateCreation wrappers.
        while (true)
        {
            switch (op)
            {
                case IAnonymousFunctionOperation anon:
                    return anon;
                case IDelegateCreationOperation dc:
                    op = dc.Target;
                    continue;
                case IConversionOperation conv:
                    op = conv.Operand;
                    continue;
                default:
                    return null;
            }
        }
    }

    private static IOperation UnwrapConversion(IOperation op)
    {
        while (op is IConversionOperation conv)
            op = conv.Operand;
        return op;
    }

    private static IEnumerable<IOperation> DescendantsOf(IAnonymousFunctionOperation anon)
    {
        // Walk every nested operation inside the lambda body.
        var stack = new Stack<IOperation>();
        stack.Push(anon.Body);
        while (stack.Count > 0)
        {
            var cur = stack.Pop();
            yield return cur;
            foreach (var child in cur.ChildOperations)
                stack.Push(child);
        }
    }

    private static IEnumerable<IPropertyReferenceOperation> CollectEncryptedMembers(IAnonymousFunctionOperation anon)
    {
        foreach (var op in DescendantsOf(anon))
        {
            if (op is IPropertyReferenceOperation pref && EncryptedSymbolHelper.HasEncryptedAttribute(pref.Property))
                yield return pref;
        }
    }
}
