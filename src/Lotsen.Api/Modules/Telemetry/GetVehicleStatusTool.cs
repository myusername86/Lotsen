using System.Text.Json;
using Lotsen.Api.Modules.Governance;

namespace Lotsen.Api.Modules.Telemetry;

/// <summary>Read tool: latest values for one vehicle, optionally limited to specific signals.</summary>
public sealed class GetVehicleStatusTool(SyntheticFleet fleet) : IAgentTool
{
    public const string ToolName = "get_vehicle_status";

    public string Name => ToolName;

    public string Description =>
        "Returns the latest telemetry values for one vehicle. Arguments: vehicleId (for example 'VH-012'), " +
        "optional signals (array of signal names). Without signals, all signals are returned.";

    public ToolEffect Effect => ToolEffect.Read;

    public ToolScope ResolveScope(JsonElement arguments)
    {
        ToolArguments.RequireObject(arguments, "vehicleId", "signals");
        string vehicleId = ToolArguments.RequireVehicleId(arguments);
        IReadOnlyList<string> signals = ToolArguments.OptionalStringArray(arguments, "signals", maxItems: 20) ?? VehicleSignals.Ordered;

        string[] unknown = signals.Where(s => !VehicleSignals.All.Contains(s)).ToArray();
        if (unknown.Length > 0)
        {
            throw new ToolArgumentException($"Unknown signals: {string.Join(", ", unknown)}.");
        }

        return new ToolScope([vehicleId], signals);
    }

    public Task<object> ExecuteAsync(ToolExecutionContext context, JsonElement arguments, CancellationToken cancellationToken)
    {
        // Same parsing as the gate used, so the tool returns exactly the scope that was approved.
        ToolScope scope = ResolveScope(arguments);
        string vehicleId = scope.VehicleIds[0];
        VehicleSnapshot? snapshot = fleet.Find(vehicleId);

        object result = snapshot is null
            ? new { vehicleId, found = false }
            : new
            {
                vehicleId,
                found = true,
                updatedAt = snapshot.UpdatedAt,
                signals = scope.Signals.ToDictionary(s => s, s => snapshot.Signals[s], StringComparer.Ordinal),
            };

        return Task.FromResult(result);
    }
}
