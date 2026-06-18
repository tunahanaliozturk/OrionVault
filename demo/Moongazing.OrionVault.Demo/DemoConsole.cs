namespace Moongazing.OrionVault.Demo;

/// <summary>Small console formatting helpers shared by the feature demos.</summary>
internal static class DemoConsole
{
    public static void Banner()
    {
        Console.WriteLine();
        Console.WriteLine("===============================================================");
        Console.WriteLine("  OrionVault Demo");
        Console.WriteLine("  Column-level AES-256-GCM encryption at rest for EF Core");
        Console.WriteLine("  In-memory static keys, SQLite in-memory. No KMS required.");
        Console.WriteLine("===============================================================");
    }

    public static void Section(int number, string title)
    {
        Console.WriteLine();
        Console.WriteLine($"---------------------------------------------------------------");
        Console.WriteLine($"  {number}. {title}");
        Console.WriteLine($"---------------------------------------------------------------");
    }

    public static void Item(string label, string value)
        => Console.WriteLine($"    {label,-26}: {value}");

    public static void Note(string text)
        => Console.WriteLine($"    > {text}");

    public static void Ok(string text)
        => Console.WriteLine($"    [OK] {text}");

    public static void Caught(string text)
        => Console.WriteLine($"    [CAUGHT] {text}");

    /// <summary>Truncate a base64 string for readable console output.</summary>
    public static string ShortB64(byte[] bytes, int head = 24)
    {
        var b64 = Convert.ToBase64String(bytes);
        return b64.Length <= head ? b64 : $"{b64[..head]}... ({b64.Length} chars)";
    }
}
