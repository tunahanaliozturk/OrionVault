namespace Moongazing.OrionVault.Analyzers;

using Microsoft.CodeAnalysis;

internal static class EncryptedSymbolHelper
{
    public const string EncryptedAttributeFullName = "Moongazing.OrionVault.EntityFrameworkCore.EncryptedAttribute";
    public const string IsEncryptedMethodFullName = "Moongazing.OrionVault.EntityFrameworkCore.PropertyBuilderExtensions.IsEncrypted";

    public static bool IsEncryptedAttribute(INamedTypeSymbol symbol)
        => symbol.ToDisplayString() == EncryptedAttributeFullName;

    public static bool HasEncryptedAttribute(IPropertySymbol prop)
    {
        foreach (var attr in prop.GetAttributes())
            if (attr.AttributeClass is { } cls && IsEncryptedAttribute(cls))
                return true;
        return false;
    }
}
