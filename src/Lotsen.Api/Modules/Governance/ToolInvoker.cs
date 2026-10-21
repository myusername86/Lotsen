using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Lotsen.Audit;

namespace Lotsen.Api.Modules.Governance;

public sealed record ToolInvocationResult(
    string RunId,
    PolicyOutcome Outcome,
    string Code,
    string Detail,
    JsonElement? Output,
    long DecisionAuditSequence);

/// <summary>
/// The only path from an agent to a tool: record the request, ask the gate, record the decision,
/// and execute only on Allow. If the audit write fails, nothing executes (fail closed).
/// </summary>
public sealed partial class ToolInvoker(PolicyGate gate, ToolCatalog tools, AuditWriter audit, ILogger<ToolInvoker> logger)
{
    public async Task<ToolInvocationResult> InvokeAsync(AgentToolRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        object? arguments = request.Arguments.ValueKind == JsonValueKind.Undefined ? null : request.Arguments;

        await audit.RecordAsync(
            AuditEventTypes.ToolRequested,
            request.AgentId,
            request.RunId,
            new { tool = request.ToolName, arguments, tainted = request.RunTainted },
            cancellationToken);

        PolicyDecision decision = gate.Evaluate(request);

        AuditEntry decisionEntry = await audit.RecordAsync(
            AuditEventTypes.PolicyDecision,
            PolicyGate.ActorId,
            request.RunId,
            new
            {
                agentId = request.AgentId,
                tool = request.ToolName,
                outcome = decision.Outcome,
                code = decision.Code,
                detail = decision.Detail,
                manifestHash = decision.ManifestHash,
                scope = decision.Scope,
            },
            cancellationToken);

        LogDecision(request.AgentId, request.ToolName, decision.Outcome, decision.Code);

        if (decision.Outcome != PolicyOutcome.Allow)
        {
            // RequireApproval is parked here until Phase 3 adds the approval queue.
            return new ToolInvocationResult(request.RunId, decision.Outcome, decision.Code, decision.Detail, null, decisionEntry.Sequence);
        }

        if (!tools.TryGet(request.ToolName, out IAgentTool? tool))
        {
            throw new InvalidOperationException("The gate allowed a tool that is not registered.");
        }

        object output;
        try
        {
            output = await tool.ExecuteAsync(new ToolExecutionContext(request.AgentId, request.RunId), request.Arguments, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await audit.RecordAsync(
                AuditEventTypes.ToolFailed,
                request.AgentId,
                request.RunId,
                new { tool = request.ToolName, error = ex.GetType().Name },
                CancellationToken.None);
            throw;
        }

        JsonElement outputJson = JsonSerializer.SerializeToElement(output, AuditWriter.PayloadSerializerOptions);
        byte[] outputBytes = Encoding.UTF8.GetBytes(CanonicalJson.Canonicalize(outputJson));

        // Store a fingerprint of the output, not the data itself, so the log stays small and holds no telemetry.
        await audit.RecordAsync(
            AuditEventTypes.ToolExecuted,
            request.AgentId,
            request.RunId,
            new
            {
                tool = request.ToolName,
                outputSha256 = Convert.ToHexStringLower(SHA256.HashData(outputBytes)),
                outputBytes = outputBytes.Length,
            },
            cancellationToken);

        return new ToolInvocationResult(request.RunId, decision.Outcome, decision.Code, decision.Detail, outputJson, decisionEntry.Sequence);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Policy decision for {AgentId} calling {Tool}: {Outcome} ({Code})")]
    private partial void LogDecision(string agentId, string tool, PolicyOutcome outcome, string code);
}
