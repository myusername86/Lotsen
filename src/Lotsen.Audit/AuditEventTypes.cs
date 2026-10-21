namespace Lotsen.Audit;

/// <summary>Stable event type names. Compliance reports and evals query on these, so never rename one.</summary>
public static class AuditEventTypes
{
    public const string ManifestLoaded = "manifest.loaded";
    public const string ToolRequested = "tool.requested";
    public const string PolicyDecision = "policy.decision";
    public const string ToolExecuted = "tool.executed";
    public const string ToolFailed = "tool.failed";
}
