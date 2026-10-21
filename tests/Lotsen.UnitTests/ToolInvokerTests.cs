using Lotsen.Api.Modules.Governance;
using Lotsen.Audit;
using Microsoft.Extensions.Logging.Abstractions;
using static Lotsen.UnitTests.TestFixtures;

namespace Lotsen.UnitTests;

public sealed class ToolInvokerTests : IDisposable
{
    private readonly FakeTool _read = new(ReadTool, ToolEffect.Read);
    private readonly FakeTool _write = new(WriteTool, ToolEffect.Write);
    private readonly InMemoryAuditStore _store = new();
    private readonly Ed25519AuditSigner _signer = Ed25519AuditSigner.FromBase64PrivateKey(Ed25519Keys.Generate().PrivateKeyBase64);

    public void Dispose()
    {
        _store.Dispose();
        _signer.Dispose();
    }

    private ToolInvoker Invoker(string manifest)
    {
        ToolCatalog catalog = Catalog(_read, _write);
        var gate = new PolicyGate(Registry(catalog, manifest), catalog);
        var audit = new AuditWriter(_store, _signer, TimeProvider.System);
        return new ToolInvoker(gate, catalog, audit, NullLogger<ToolInvoker>.Instance);
    }

    [Fact]
    public async Task AllowedCall_ExecutesAndRecordsThreeEntries()
    {
        ToolInvocationResult result = await Invoker(Manifest()).InvokeAsync(
            new AgentToolRequest("agent.test", "run_1", ReadTool, Args(), false), CancellationToken.None);

        Assert.Equal(PolicyOutcome.Allow, result.Outcome);
        Assert.NotNull(result.Output);
        Assert.Equal(1, _read.ExecutionCount);

        string[] events = (await _store.ReadPageAsync(0, 10, CancellationToken.None)).Select(e => e.EventType).ToArray();
        Assert.Equal(new[] { AuditEventTypes.ToolRequested, AuditEventTypes.PolicyDecision, AuditEventTypes.ToolExecuted }, events);
    }

    [Fact]
    public async Task DeniedCall_NeverExecutesButIsStillRecorded()
    {
        ToolInvocationResult result = await Invoker(Manifest(autonomy: "read-only")).InvokeAsync(
            new AgentToolRequest("agent.test", "run_1", WriteTool, Args(), false), CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, result.Outcome);
        Assert.Equal(0, _write.ExecutionCount);

        var entries = await _store.ReadPageAsync(0, 10, CancellationToken.None);
        Assert.Equal(2, entries.Count);
        Assert.Contains(PolicyCodes.WriteNotPermitted, entries[1].Payload, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ApprovalRequiredCall_DoesNotExecute()
    {
        ToolInvocationResult result = await Invoker(Manifest(autonomy: "ask-first")).InvokeAsync(
            new AgentToolRequest("agent.test", "run_1", WriteTool, Args(), false), CancellationToken.None);

        Assert.Equal(PolicyOutcome.RequireApproval, result.Outcome);
        Assert.Equal(0, _write.ExecutionCount);
    }
}
