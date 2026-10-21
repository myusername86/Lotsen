using System.Text.Json;
using Lotsen.Api.Modules.Governance;

namespace Lotsen.UnitTests;

/// <summary>A tool that only parses arguments, so gate tests do not depend on real telemetry.</summary>
internal sealed class FakeTool(string name, ToolEffect effect) : IAgentTool
{
    public string Name { get; } = name;

    public string Description => "Test tool.";

    public ToolEffect Effect { get; } = effect;

    public int ExecutionCount { get; private set; }

    public ToolScope ResolveScope(JsonElement arguments)
    {
        ToolArguments.RequireObject(arguments, "vehicleId", "signals");
        string vehicleId = ToolArguments.RequireVehicleId(arguments);
        IReadOnlyList<string> signals = ToolArguments.OptionalStringArray(arguments, "signals", 10) ?? [];
        return new ToolScope([vehicleId], signals);
    }

    public Task<object> ExecuteAsync(ToolExecutionContext context, JsonElement arguments, CancellationToken cancellationToken)
    {
        ExecutionCount++;
        return Task.FromResult<object>(new { ok = true });
    }
}

internal static class TestFixtures
{
    public const string ReadTool = "read_status";
    public const string WriteTool = "create_ticket";

    public static readonly IReadOnlySet<string> Signals =
        new HashSet<string>(["engine_temp_c", "speed_kmh", "battery_soc_pct"], StringComparer.Ordinal);

    public static string Manifest(
        string agentId = "agent.test",
        string autonomy = "auto",
        string[]? tools = null,
        string[]? vehicles = null,
        string[]? signals = null,
        bool enabled = true) =>
        JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            agentId,
            name = "Test Agent",
            description = "Used in tests.",
            owner = new { id = "user.tester", name = "Tester" },
            enabled,
            autonomy,
            tools = tools ?? [ReadTool, WriteTool],
            dataScope = new { vehicles = vehicles ?? ["*"], signals = signals ?? ["*"] },
            budget = new { maxTokensPerDay = 1000, maxCostPerDayUsd = 1.0m },
        });

    public static ToolCatalog Catalog(params IAgentTool[] tools) =>
        new(tools.Length > 0 ? tools : [new FakeTool(ReadTool, ToolEffect.Read), new FakeTool(WriteTool, ToolEffect.Write)]);

    public static AgentRegistry Registry(ToolCatalog catalog, params string[] manifests) =>
        AgentRegistry.FromJson(manifests.Select((json, i) => ($"manifest-{i}.json", json)), catalog.Names, Signals);

    public static JsonElement Args(string vehicleId = "VH-001", string[]? signals = null) =>
        JsonSerializer.SerializeToElement(signals is null ? new { vehicleId } : (object)new { vehicleId, signals });

    public static JsonElement Json(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }
}
