namespace Moongazing.OrionVault.EntityFrameworkCore;

/// <summary>
/// Marks a property for transparent at-rest encryption. Supported CLR types
/// are <see cref="string"/> and <c>byte[]</c>. Other types produce analyzer
/// error <c>OV0001</c> at compile time.
/// </summary>
[AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
public sealed class EncryptedAttribute : Attribute { }
