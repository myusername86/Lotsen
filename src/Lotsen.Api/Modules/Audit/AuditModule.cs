using Lotsen.Audit;

namespace Lotsen.Api.Modules.Audit;

public static class AuditModule
{
    public static WebApplicationBuilder AddAuditModule(this WebApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        IConfigurationSection section = builder.Configuration.GetSection("Audit");
        var services = builder.Services;

        // The private key comes only from user-secrets, an environment variable or Key Vault. Never from a file in the repo.
        services.AddSingleton(_ =>
        {
            string? privateKey = section["SigningPrivateKey"];
            if (string.IsNullOrWhiteSpace(privateKey))
            {
                throw new InvalidOperationException(
                    "Audit:SigningPrivateKey is not configured. Run 'dotnet run --project src/Lotsen.Cli -- keygen' " +
                    "and store the private key in user-secrets or the Audit__SigningPrivateKey environment variable.");
            }

            return Ed25519AuditSigner.FromBase64PrivateKey(privateKey);
        });
        services.AddSingleton<IAuditSigner>(sp => sp.GetRequiredService<Ed25519AuditSigner>());

        // Trusted keys = the current key plus any retired keys, so older entries still verify after rotation.
        services.AddSingleton<IAuditSignatureVerifier>(sp =>
        {
            string[] retiredKeys = section.GetSection("TrustedPublicKeys").Get<string[]>() ?? [];
            string currentKey = sp.GetRequiredService<Ed25519AuditSigner>().PublicKeyBase64;
            return new Ed25519SignatureVerifier([currentKey, .. retiredKeys]);
        });

        string store = section["Store"] ?? "Postgres";
        if (string.Equals(store, "Postgres", StringComparison.OrdinalIgnoreCase))
        {
            string connectionString = builder.Configuration.GetConnectionString("Lotsen")
                ?? throw new InvalidOperationException(
                    "ConnectionStrings:Lotsen is not configured. Set it in user-secrets or the ConnectionStrings__Lotsen environment variable.");
            services.AddSingleton(_ => new PostgresAuditStore(connectionString));
            services.AddSingleton<IAuditStore>(sp => sp.GetRequiredService<PostgresAuditStore>());
        }
        else if (string.Equals(store, "InMemory", StringComparison.OrdinalIgnoreCase))
        {
            if (!builder.Environment.IsDevelopment() && !builder.Environment.IsEnvironment("Testing"))
            {
                throw new InvalidOperationException("The in-memory audit store is only allowed in Development and Testing.");
            }

            services.AddSingleton<IAuditStore, InMemoryAuditStore>();
        }
        else
        {
            throw new InvalidOperationException($"Unknown Audit:Store '{store}'. Use 'Postgres' or 'InMemory'.");
        }

        services.AddSingleton<AuditWriter>();
        services.AddSingleton<AuditVerifier>();
        return builder;
    }

    public static async Task InitializeAuditAsync(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Resolving the signer here validates the key at startup instead of on the first request.
        _ = app.Services.GetRequiredService<IAuditSigner>();

        if (app.Services.GetService<PostgresAuditStore>() is { } postgres &&
            app.Configuration.GetValue("Audit:ApplySchemaOnStartup", true))
        {
            await postgres.EnsureSchemaAsync(app.Lifetime.ApplicationStopping);
        }
    }
}
