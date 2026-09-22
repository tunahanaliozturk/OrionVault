namespace Moongazing.OrionVault.EntityFrameworkCore;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Moongazing.OrionVault.EntityFrameworkCore.Internal;

/// <summary>
/// Adds the bound key material to EF Core's compiled-model cache key, so two hosts of the SAME
/// DbContext CLR type wired to DIFFERENT keys get different compiled models.
/// </summary>
/// <remarks>
/// <para>
/// OrionVault's value converters capture one <see cref="Abstractions.IEncryptor"/> by closure, and
/// the converters live on the compiled model. EF Core's default <c>IModelCacheKeyFactory</c> keys
/// that model on the DbContext type (and the design-time flag) alone, and the model cache is
/// process-wide - so without this replacement whichever host built the model first lends its
/// encryptor to every later host of the same type, and one tenant reads another's plaintext.
/// </para>
/// <para>
/// Wired automatically by <c>UseOrionVault(sp)</c>, <c>AddOrionVaultDbContext&lt;T&gt;</c> and
/// <c>AddOrionVaultBoundDbContext&lt;T&gt;</c>. Wire it yourself alongside
/// <see cref="KeyedOrionVaultModelCustomizer{TDbContext}"/> if you assemble the options by hand:
/// <c>opt.ReplaceService&lt;IModelCacheKeyFactory, OrionVaultModelCacheKeyFactory&gt;()</c>.
/// </para>
/// </remarks>
public sealed class OrionVaultModelCacheKeyFactory : IModelCacheKeyFactory
{
    /// <inheritdoc />
    public object Create(DbContext context, bool designTime)
    {
        ArgumentNullException.ThrowIfNull(context);
        return (context.GetType(), designTime, KeySetFingerprint.ForContext(context));
    }
}
