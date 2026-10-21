using System.Collections.Concurrent;
using System.Text.Json;
using Lotsen.Api.Modules.Governance;

namespace Lotsen.Api.Modules.Maintenance;

public sealed record MaintenanceTicket(
    string Id,
    string VehicleId,
    string Title,
    string Priority,
    string Description,
    string CreatedByAgentId,
    string RunId,
    DateTimeOffset CreatedAt);

/// <summary>In-memory for Phase 1. Moves to PostgreSQL together with the approval queue in Phase 3.</summary>
public sealed class MaintenanceTicketStore
{
    private readonly ConcurrentQueue<MaintenanceTicket> _tickets = new();

    public IEnumerable<MaintenanceTicket> All => _tickets.OrderByDescending(t => t.CreatedAt);

    public void Add(MaintenanceTicket ticket) => _tickets.Enqueue(ticket);
}

/// <summary>Write tool. Under an ask-first manifest the gate never lets this run without a person.</summary>
public sealed class CreateMaintenanceTicketTool(MaintenanceTicketStore store, TimeProvider timeProvider) : IAgentTool
{
    public const string ToolName = "create_maintenance_ticket";
    private static readonly string[] Priorities = ["low", "medium", "high"];

    public string Name => ToolName;

    public string Description =>
        "Creates a maintenance ticket for one vehicle. Arguments: vehicleId, title (max 120 chars), " +
        "priority ('low', 'medium' or 'high'), description (max 2000 chars).";

    public ToolEffect Effect => ToolEffect.Write;

    public ToolScope ResolveScope(JsonElement arguments)
    {
        ToolArguments.RequireObject(arguments, "vehicleId", "title", "priority", "description");
        string vehicleId = ToolArguments.RequireVehicleId(arguments);
        ToolArguments.RequireString(arguments, "title", 120);
        ToolArguments.RequireOneOf(arguments, "priority", Priorities);
        ToolArguments.RequireString(arguments, "description", 2000);
        return new ToolScope([vehicleId], []);
    }

    public Task<object> ExecuteAsync(ToolExecutionContext context, JsonElement arguments, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ResolveScope(arguments);

        var ticket = new MaintenanceTicket(
            Id: "MT-" + Guid.CreateVersion7().ToString("N")[..12].ToUpperInvariant(),
            VehicleId: ToolArguments.RequireVehicleId(arguments),
            Title: ToolArguments.RequireString(arguments, "title", 120),
            Priority: ToolArguments.RequireOneOf(arguments, "priority", Priorities),
            Description: ToolArguments.RequireString(arguments, "description", 2000),
            CreatedByAgentId: context.AgentId,
            RunId: context.RunId,
            CreatedAt: timeProvider.GetUtcNow());

        store.Add(ticket);
        return Task.FromResult<object>(new { ticketId = ticket.Id, ticket.VehicleId, ticket.Priority });
    }
}
