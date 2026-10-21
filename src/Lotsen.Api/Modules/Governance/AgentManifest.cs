namespace Lotsen.Api.Modules.Governance;

/// <summary>How much an agent may do without a person. Serialized as "read-only", "ask-first", "auto".</summary>
public enum AutonomyLevel
{
    ReadOnly,
    AskFirst,
    Auto,
}

/// <summary>The human accountable for an agent.</summary>
public sealed record AgentOwner(string Id, string Name);

public sealed record DataScope(IReadOnlyList<string> Vehicles, IReadOnlyList<string> Signals)
{
    public const string Wildcard = "*";

    public bool AllowsVehicle(string vehicleId) =>
        Vehicles.Contains(Wildcard, StringComparer.Ordinal) || Vehicles.Contains(vehicleId, StringComparer.Ordinal);

    public bool AllowsSignal(string signal) =>
        Signals.Contains(Wildcard, StringComparer.Ordinal) || Signals.Contains(signal, StringComparer.Ordinal);
}

/// <summary>Daily limits. Enforced by the model gateway in Phase 2.</summary>
public sealed record AgentBudget(long MaxTokensPerDay, decimal MaxCostPerDayUsd);

/// <summary>The policy an agent runs under. Loaded from agents/*.json and reviewed like code.</summary>
public sealed record AgentManifest(
    int SchemaVersion,
    string AgentId,
    string Name,
    string Description,
    AgentOwner Owner,
    bool Enabled,
    AutonomyLevel Autonomy,
    IReadOnlyList<string> Tools,
    DataScope DataScope,
    AgentBudget Budget);

/// <summary>
/// An agent as a security principal: its own identity, a human owner, and the exact
/// manifest version (by hash) that governs it.
/// </summary>
public sealed record AgentPrincipal(AgentManifest Manifest, string ManifestHash, string SourceFile)
{
    public string AgentId => Manifest.AgentId;
}
