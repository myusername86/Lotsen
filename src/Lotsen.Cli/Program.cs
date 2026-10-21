using Lotsen.Audit;

// Lotsen CLI.
//   keygen        Create a new Ed25519 audit signing key pair.
//   verify-audit  Verify the full audit chain directly from PostgreSQL, using public keys only.
//
// The verifier is deliberately independent of the API: an auditor needs only database read access
// and the public key, never the private key or a running application.

if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
{
    PrintHelp();
    return 0;
}

return args[0] switch
{
    "keygen" => KeyGen(),
    "verify-audit" => await VerifyAuditAsync(args[1..]),
    _ => UnknownCommand(args[0]),
};

static int KeyGen()
{
    AuditKeyPair keys = Ed25519Keys.Generate();
    Console.WriteLine("New Ed25519 audit signing key pair");
    Console.WriteLine();
    Console.WriteLine($"Key id:       {keys.KeyId}");
    Console.WriteLine($"Public key:   {keys.PublicKeyBase64}");
    Console.WriteLine($"Private key:  {keys.PrivateKeyBase64}");
    Console.WriteLine();
    Console.WriteLine("Store the PRIVATE key as a secret only (never commit it):");
    Console.WriteLine("  dotnet user-secrets set \"Audit:SigningPrivateKey\" \"<private key>\" --project src/Lotsen.Api");
    Console.WriteLine("  or the Audit__SigningPrivateKey environment variable, or Azure Key Vault in the cloud.");
    Console.WriteLine();
    Console.WriteLine("Share the PUBLIC key with anyone who needs to verify the log.");
    return 0;
}

static async Task<int> VerifyAuditAsync(string[] options)
{
    // Prefer environment variables: a connection string on the command line ends up in shell history.
    string? connection = GetOption(options, "--connection") ?? Environment.GetEnvironmentVariable("LOTSEN_DB");
    List<string> publicKeys = GetOptions(options, "--public-key")
        .Concat((Environment.GetEnvironmentVariable("AUDIT_PUBLIC_KEYS") ?? string.Empty)
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        .ToList();

    if (string.IsNullOrWhiteSpace(connection) || publicKeys.Count == 0)
    {
        Console.Error.WriteLine("verify-audit needs a connection string and at least one public key.");
        Console.Error.WriteLine("Set LOTSEN_DB and AUDIT_PUBLIC_KEYS, or pass --connection and --public-key.");
        return 2;
    }

    await using var store = new PostgresAuditStore(connection);
    var verifier = new AuditVerifier(new Ed25519SignatureVerifier(publicKeys));
    AuditVerificationResult result = await verifier.VerifyAsync(store.ReadAllAsync(CancellationToken.None), CancellationToken.None);

    if (result.IsValid)
    {
        Console.WriteLine($"VALID  {result.EntriesChecked} entries verified.");
        Console.WriteLine($"Head hash: {result.HeadHash}");
        return 0;
    }

    Console.WriteLine($"INVALID  chain breaks at sequence {result.FailedAtSequence}.");
    Console.WriteLine($"Reason: {result.Failure}");
    Console.WriteLine($"Entries verified before the break: {result.EntriesChecked}");
    return 1;
}

static string? GetOption(string[] options, string name) => GetOptions(options, name).LastOrDefault();

static IEnumerable<string> GetOptions(string[] options, string name)
{
    for (int i = 0; i < options.Length - 1; i++)
    {
        if (string.Equals(options[i], name, StringComparison.Ordinal))
        {
            yield return options[i + 1];
        }
    }
}

static int UnknownCommand(string command)
{
    Console.Error.WriteLine($"Unknown command '{command}'.");
    PrintHelp();
    return 2;
}

static void PrintHelp()
{
    Console.WriteLine("Usage: lotsen <command> [options]");
    Console.WriteLine();
    Console.WriteLine("Commands:");
    Console.WriteLine("  keygen                     Generate an Ed25519 audit signing key pair.");
    Console.WriteLine("  verify-audit               Verify every hash, link and signature in the audit log.");
    Console.WriteLine("      --connection <value>   PostgreSQL connection string (or env LOTSEN_DB).");
    Console.WriteLine("      --public-key <base64>  Trusted public key, repeatable (or env AUDIT_PUBLIC_KEYS, comma-separated).");
    Console.WriteLine();
    Console.WriteLine("Exit codes: 0 valid, 1 tampering detected, 2 usage error.");
}
