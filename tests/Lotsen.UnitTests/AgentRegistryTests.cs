using Lotsen.Api.Modules.Governance;
using static Lotsen.UnitTests.TestFixtures;

namespace Lotsen.UnitTests;

public sealed class AgentRegistryTests
{
    [Fact]
    public void ValidManifest_LoadsAsPrincipalWithOwner()
    {
        AgentRegistry registry = Registry(Catalog(), Manifest(autonomy: "ask-first"));

        Assert.True(registry.TryGet("agent.test", out AgentPrincipal? agent));
        Assert.Equal("user.tester", agent.Manifest.Owner.Id);
        Assert.Equal(AutonomyLevel.AskFirst, agent.Manifest.Autonomy);
        Assert.StartsWith("sha256:", agent.ManifestHash, StringComparison.Ordinal);
    }

    [Fact]
    public void UnknownProperty_IsRejected()
    {
        // A typo like "tool" instead of "tools" must fail loudly rather than load an agent with no limits.
        string json = Manifest().Replace("\"enabled\":true", "\"enabled\":true,\"superuser\":true", StringComparison.Ordinal);

        var ex = Assert.Throws<ManifestValidationException>(() => Registry(Catalog(), json));
        Assert.Contains(ex.Errors, e => e.Contains("superuser", StringComparison.Ordinal));
    }

    [Fact]
    public void MissingRequiredProperty_IsRejected()
    {
        string json = """
            { "schemaVersion": 1, "agentId": "agent.test", "name": "Test", "description": "x",
              "owner": { "id": "user.tester", "name": "Tester" }, "enabled": true, "autonomy": "auto",
              "tools": [], "budget": { "maxTokensPerDay": 10, "maxCostPerDayUsd": 1 } }
            """;

        Assert.Throws<ManifestValidationException>(() => Registry(Catalog(), json));
    }

    [Fact]
    public void UnregisteredTool_IsRejected()
    {
        var ex = Assert.Throws<ManifestValidationException>(() =>
            Registry(Catalog(), Manifest(tools: ["delete_everything"])));

        Assert.Contains(ex.Errors, e => e.Contains("delete_everything", StringComparison.Ordinal));
    }

    [Fact]
    public void UnknownSignal_IsRejected()
    {
        Assert.Throws<ManifestValidationException>(() => Registry(Catalog(), Manifest(signals: ["driver_home_address"])));
    }

    [Theory]
    [InlineData("anomaly")]
    [InlineData("agent.Anomaly")]
    [InlineData("agent.")]
    public void BadAgentId_IsRejected(string agentId)
    {
        Assert.Throws<ManifestValidationException>(() => Registry(Catalog(), Manifest(agentId: agentId)));
    }

    [Fact]
    public void UnknownAutonomyLevel_IsRejected()
    {
        Assert.Throws<ManifestValidationException>(() => Registry(Catalog(), Manifest(autonomy: "god-mode")));
    }

    [Fact]
    public void DuplicateAgentId_IsRejected()
    {
        Assert.Throws<ManifestValidationException>(() => Registry(Catalog(), Manifest(), Manifest()));
    }

    [Fact]
    public void ManifestHash_IgnoresFormattingButNotContent()
    {
        string compact = """{"b":1,"a":[1,2]}""";
        string reformatted = """
            {
              "a": [1, 2],
              "b": 1
            }
            """;
        string changed = """{"a":[1,2],"b":2}""";

        Assert.Equal(AgentRegistry.ComputeHash(compact), AgentRegistry.ComputeHash(reformatted));
        Assert.NotEqual(AgentRegistry.ComputeHash(compact), AgentRegistry.ComputeHash(changed));
    }
}
