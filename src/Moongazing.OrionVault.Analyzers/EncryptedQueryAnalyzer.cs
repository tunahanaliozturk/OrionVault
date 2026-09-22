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
        title: "Filtering on an encrypted column matches no rows",
        messageFormat: "Filtering on encrypted column '{0}' reaches the database as SQL evaluated against random ciphertext, so it matches nothing and reports success - a search renders empty, an ExecuteDelete deletes no rows. Use a separate blind-index column for searchable encrypted values, or materialise the query and filter in memory.",
        category: "Moongazing.OrionVault",
        // Error, not Warning: the predicate is silently false for every row, and the failure mode
        // is a screen that renders empty or a GDPR erasure that deletes nothing and reports
        // success. There is no intentional version of this query, so a build that stops is
        // cheaper than the data loss. Suppress with <NoWarn>OV0002</NoWarn> if you disagree.
        defaultSeverity: DiagnosticSeverity.Error,
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
        // Queryable only. Enumerable operators run over values the value converter has already
        // decrypted, where comparing a plaintext string is correct - flagging those would make an
        // Error-severity rule fire on working code.
        if (method.ContainingType?.ToDisplayString() != "System.Linq.Queryable")
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
                switch (op)
                {
                    case IBinaryOperation bin:
                        ReportBinaryComparison(bin, ctx);
                        break;

                    // Contains / StartsWith / EndsWith / string.Equals / EF.Functions.Like /
                    // emails.Contains(u.Email) - every one of these translates to SQL over the
                    // ciphertext just as `==` does, and none of them is an IBinaryOperation.
                    case IInvocationOperation call:
                        ReportInvocationOperand(call, ctx);
                        break;
                }
            }
        }
    }

    private static void ReportBinaryComparison(IBinaryOperation bin, OperationAnalysisContext ctx)
    {
        if (bin.OperatorKind is not (BinaryOperatorKind.Equals or BinaryOperatorKind.NotEquals)) return;
        ReportIfEncryptedOperand(bin, new[] { bin.LeftOperand, bin.RightOperand }, ctx);
    }

    private static void ReportInvocationOperand(IInvocationOperation call, OperationAnalysisContext ctx)
    {
        var operands = new List<IOperation?>(call.Arguments.Length + 1) { call.Instance };
        foreach (var argument in call.Arguments)
            operands.Add(argument.Value);

        ReportIfEncryptedOperand(call, operands, ctx);
    }

    /// <summary>
    /// Decides one comparison site. The rule is about the operands, not about which syntax
    /// carries them, so binary and invocation forms route through here and cannot drift apart.
    /// </summary>
    private static void ReportIfEncryptedOperand(
        IOperation site, IEnumerable<IOperation?> operands, OperationAnalysisContext ctx)
    {
        IPropertySymbol? property = null;

        foreach (var operand in operands)
        {
            if (operand is null) continue;

            // A null operand makes the whole comparison a null test whatever syntax reaches it -
            // `col == null`, `string.Equals(col, null)`, `object.Equals(col, null)`,
            // `col.Equals(null)`, `ReferenceEquals(col, null)`. Providers translate all of them to
            // IS NULL, which is evaluated against the column rather than its contents and so works
            // correctly on ciphertext. Checked across every operand before reporting, because an
            // encrypted operand found first must not pre-empt a null found second.
            if (IsNullLiteral(operand)) return;

            // One diagnostic per site: an encrypted column in any operand is enough, and reporting
            // per operand would stack duplicates on the same span.
            property ??= EncryptedPropertyOf(operand);
        }

        if (property is not null)
            ctx.ReportDiagnostic(Diagnostic.Create(WhereRule, site.Syntax.GetLocation(), property.Name));
    }

    private static IPropertySymbol? EncryptedPropertyOf(IOperation? op)
    {
        if (op is null) return null;
        return UnwrapConversion(op) is IPropertyReferenceOperation reference
            && EncryptedSymbolHelper.HasEncryptedAttribute(reference.Property)
            ? reference.Property
            : null;
    }

    private static bool IsNullLiteral(IOperation op)
        => UnwrapConversion(op).ConstantValue is { HasValue: true, Value: null };

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
