using System.Text.Json;

namespace Lotsen.Api.Modules.Governance;

public enum PolicyOutcome
{
    Allow,
    RequireApproval,
    Deny,
}

/// <summary>Stable decision codes. Evals and compliance reports count on these.</summary>
public static class PolicyCodes
{
    public const string Allowed = "allowed";
    public const string UnknownAgent = "unknown_agent";
    public const string AgentDisabled = "agent_disabled";
    public const string ToolNotAllowed = "tool_not_allowed";
    public const string ToolNotRegistered = "tool_not_registered";
    public const string InvalidArguments = "invalid_arguments";
    public const string VehicleOutOfScope = "vehicle_out_of_scope";
    public const string SignalOutOfScope = "signal_out_of_scope";
    public const string WriteNotPermitted = "write_not_permitted";
    public const string ApprovalRequiredAskFirst = "approval_required_ask_first";
    public const string ApprovalRequiredTainted = "approval_required_tainted";
}

/// <summary>A proposed action. AgentId and RunTainted are set by the server, never by model output.</summary>
public sealed record AgentToolRequest(
    string AgentId,
    string RunId,
    string ToolName,
    JsonElement Arguments,
    bool RunTainted);

public sealed record PolicyDecision(
    PolicyOutcome Outcome,
    string Code,
    string Detail,
    string? ManifestHash,
    ToolScope? Scope)
{
    public static PolicyDecision Deny(string code, string detail, string? manifestHash = null, ToolScope? scope = null) =>
        new(PolicyOutcome.Deny, code, detail, manifestHash, scope);

    public static PolicyDecision Approval(string code, string detail, string manifestHash, ToolScope scope) =>
        new(PolicyOutcome.RequireApproval, code, detail, manifestHash, scope);

    public static PolicyDecision Allow(string manifestHash, ToolScope scope) =>
        new(PolicyOutcome.Allow, PolicyCodes.Allowed, "Action is within the agent's manifest.", manifestHash, scope);
}

/// <summary>
/// The single checkpoint between what a model asks for and what actually happens.
/// Deny by default: every check must pass, and the first failure wins.
/// Pure and synchronous, so it is fast and fully unit-testable.
/// </summary>
public sealed class PolicyGate(AgentRegistry agents, ToolCatalog tools)
{
    public const string ActorId = "system.policy-gate";

    public PolicyDecision Evaluate(AgentToolRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!agents.TryGet(request.AgentId, out AgentPrincipal? agent))
        {
            return PolicyDecision.Deny(PolicyCodes.UnknownAgent, "No manifest exists for this agent.");
        }

        AgentManifest manifest = agent.Manifest;
        string hash = agent.ManifestHash;

        if (!manifest.Enabled)
        {
            return PolicyDecision.Deny(PolicyCodes.AgentDisabled, "The agent is disabled by its owner.", hash);
        }

        if (!manifest.Tools.Contains(request.ToolName, StringComparer.Ordinal))
        {
            return PolicyDecision.Deny(PolicyCodes.ToolNotAllowed, $"Tool '{request.ToolName}' is not in the manifest allow-list.", hash);
        }

        if (!tools.TryGet(request.ToolName, out IAgentTool? tool))
        {
            return PolicyDecision.Deny(PolicyCodes.ToolNotRegistered, $"Tool '{request.ToolName}' is not registered.", hash);
        }

        ToolScope scope;
        try
        {
            scope = tool.ResolveScope(request.Arguments);
        }
        catch (ToolArgumentException ex)
        {
            return PolicyDecision.Deny(PolicyCodes.InvalidArguments, ex.Message, hash);
        }

        string[] blockedVehicles = scope.VehicleIds.Where(v => !manifest.DataScope.AllowsVehicle(v)).ToArray();
        if (blockedVehicles.Length > 0)
        {
            return PolicyDecision.Deny(
                PolicyCodes.VehicleOutOfScope, $"Vehicles outside data scope: {string.Join(", ", blockedVehicles)}.", hash, scope);
        }

        string[] blockedSignals = scope.Signals.Where(s => !manifest.DataScope.AllowsSignal(s)).ToArray();
        if (blockedSignals.Length > 0)
        {
            return PolicyDecision.Deny(
                PolicyCodes.SignalOutOfScope, $"Signals outside data scope: {string.Join(", ", blockedSignals)}.", hash, scope);
        }

        if (tool.Effect == ToolEffect.Write)
        {
            if (manifest.Autonomy == AutonomyLevel.ReadOnly)
            {
                return PolicyDecision.Deny(PolicyCodes.WriteNotPermitted, "A read-only agent cannot use write tools.", hash, scope);
            }

            if (manifest.Autonomy == AutonomyLevel.AskFirst)
            {
                return PolicyDecision.Approval(
                    PolicyCodes.ApprovalRequiredAskFirst, "The agent's autonomy level requires human approval.", hash, scope);
            }

            // Taint can only make the policy stricter, never looser.
            if (request.RunTainted)
            {
                return PolicyDecision.Approval(
                    PolicyCodes.ApprovalRequiredTainted, "This run read untrusted content, so a person must approve.", hash, scope);
            }
        }

        return PolicyDecision.Allow(hash, scope);
    }
}
