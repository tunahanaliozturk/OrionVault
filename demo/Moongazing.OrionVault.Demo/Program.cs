using Moongazing.OrionVault.Demo;

DemoConsole.Banner();

// Pure-cipher demos (no database).
EncryptRoundTripDemo.Run();
RandomizedCiphertextDemo.Run();
KeyRotationDemo.Run();
TamperDetectionDemo.Run();

// EF Core integration demos (SQLite in-memory).
await EfCoreColumnEncryptionDemo.RunAsync();
await SearchableIndexDemo.RunAsync();
await BlindIndexDemo.RunAsync();

Console.WriteLine();
Console.WriteLine("===============================================================");
Console.WriteLine("  All OrionVault demos completed.");
Console.WriteLine("===============================================================");
