using System.Text.Json;
using System.Text.RegularExpressions;
using Lotsen.Api.Modules.Telemetry;
using Lotsen.Audit;

namespace Lotsen.Api.Modules.Governance;

public static partial class GovernanceModule
{
    public const string ActorId = "system.governance";

    public static WebApplicationBuilder AddGovernanceModule(this WebApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        string configured = builder.Configuration["Governance:ManifestDirectory"] ?? "agents";
        string directory = Path.IsPathRooted(configured) ? configured : Path.Combine(AppContext.BaseDirectory, configured);

        builder.Services.AddSingleton<ToolCatalog>();
        builder.Services.AddSingleton(sp =>
            AgentRegistry.LoadFromDirectory(directory, sp.GetRequiredService<ToolCatalog>().Names, VehicleSignals.All));
        builder.Services.AddSingleton<PolicyGate>();
        builder.Services.AddSingleton<ToolInvoker>();
        return builder;
    }

    /// <summary>Loads manifests (failing startup if any is invalid) and records which policy versions are active.</summary>
    public static async Task InitializeGovernanceAsync(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);
        var registry = app.Services.GetRequiredService<AgentRegistry>();
        var audit = app.Services.GetRequiredService<AuditWriter>();

        foreach (AgentPrincipal agent in registry.All.OrderBy(a => a.AgentId, StringComparer.Ordinal))
        {
            await audit.RecordAsync(
                AuditEventTypes.ManifestLoaded,
                ActorId,
                runId: null,
                new
                {
                    agentId = agent.AgentId,
                    ownerId = agent.Manifest.Owner.Id,
                    autonomy = agent.Manifest.Autonomy,
                    tools = agent.Manifest.Tools,
                    manifestHash = agent.ManifestHash,
                    source = agent.SourceFile,
                },
                app.Lifetime.ApplicationStopping);
        }
    }

    public static IEndpointRouteBuilder MapGovernanceEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        app.MapGet("/api/agents", (AgentRegistry registry) =>
                registry.All
                    .OrderBy(a => a.AgentId, StringComparer.Ordinal)
                    .Select(a => new AgentSummary(
                        a.AgentId,
                        a.Manifest.Name,
                        a.Manifest.Description,
                        a.Manifest.Owner,
                        a.Manifest.Enabled,
                        a.Manifest.Autonomy,
                        a.Manifest.Tools,
                        a.Manifest.DataScope,
                        a.Manifest.Budget,
                        a.ManifestHash)))
            .WithTags("Agents");

        // Phase 1 stand-in for the agent runtime: lets you propose tool calls by hand and watch the gate decide.
        // Development only. From Phase 2 the runtime sets agent identity and taint server-side.
        var environment = app.ServiceProvider.GetRequiredService<IWebHostEnvironment>();
        if (environment.IsDevelopment())
        {
            app.MapPost("/api/dev/agents/{agentId}/tool-calls", async (
                    string agentId, DevToolCallRequest body, ToolInvoker invoker, CancellationToken ct) =>
                {
                    if (string.IsNullOrWhiteSpace(body.Tool) || body.Tool.Length > 64)
                    {
                        return Results.ValidationProblem(new Dictionary<string, string[]> { ["tool"] = ["Tool name is required (max 64 characters)."] });
                    }

                    if (body.RunId is not null && !RunIdPattern().IsMatch(body.RunId))
                    {
                        return Results.ValidationProblem(new Dictionary<string, string[]> { ["runId"] = ["Run id must look like 'run_' followed by 32 hex characters."] });
                    }

                    var request = new AgentToolRequest(agentId, body.RunId ?? RunIds.New(), body.Tool, body.Arguments, body.Tainted);
                    ToolInvocationResult result = await invoker.InvokeAsync(request, ct);

                    return result.Outcome switch
                    {
                        PolicyOutcome.Allow => Results.Ok(result),
                        PolicyOutcome.RequireApproval => Results.Accepted(uri: null, value: result),
                        _ => Results.Json(result, statusCode: StatusCodes.Status403Forbidden),
                    };
                })
                .WithTags("Development");
        }

        return app;
    }

    [GeneratedRegex("^run_[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex RunIdPattern();
}

public static class RunIds
{
    public static string New() => "run_" + Guid.CreateVersion7().ToString("N");
}

public sealed record AgentSummary(
    string AgentId,
    string Name,
    string Description,
    AgentOwner Owner,
    bool Enabled,
    AutonomyLevel Autonomy,
    IReadOnlyList<string> Tools,
    DataScope DataScope,
    AgentBudget Budget,
    string ManifestHash);

public sealed record DevToolCallRequest(string Tool, JsonElement Arguments, string? RunId = null, bool Tainted = false);
