namespace Moongazing.OrionVault.EntityFrameworkCore;

using Microsoft.EntityFrameworkCore.Metadata.Builders;

public static class PropertyBuilderExtensions
{
    internal const string EncryptedAnnotation = "OrionVault:Encrypted";

    public static PropertyBuilder<string> IsEncrypted(this PropertyBuilder<string> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.HasAnnotation(EncryptedAnnotation, true);
        return builder;
    }

    public static PropertyBuilder<byte[]> IsEncrypted(this PropertyBuilder<byte[]> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.HasAnnotation(EncryptedAnnotation, true);
        return builder;
    }
}
