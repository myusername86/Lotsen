using System.Diagnostics.CodeAnalysis;
using Lotsen.Audit;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Lotsen.IntegrationTests;

/// <summary>Runs against a real PostgreSQL in Docker. Requires Docker locally; GitHub's Ubuntu runners have it.</summary>
[SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "xUnit disposes these through IAsyncLifetime.DisposeAsync.")]
public sealed class PostgresAuditStoreTests : IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder("pgvector/pgvector:pg17").Build();

    private readonly AuditKeyPair _keys = Ed25519Keys.Generate();
    private PostgresAuditStore _store = null!;
    private Ed25519AuditSigner _signer = null!;
    private AuditWriter _writer = null!;
    private AuditVerifier _verifier = null!;

    public async Task InitializeAsync()
    {
        await _postgres.StartAsync();
        _store = new PostgresAuditStore(_postgres.GetConnectionString());
        await _store.EnsureSchemaAsync(CancellationToken.None);
        _signer = Ed25519AuditSigner.FromBase64PrivateKey(_keys.PrivateKeyBase64);
        _writer = new AuditWriter(_store, _signer, TimeProvider.System);
        _verifier = new AuditVerifier(new Ed25519SignatureVerifier([_keys.PublicKeyBase64]));
    }

    public async Task DisposeAsync()
    {
        _signer.Dispose();
        await _store.DisposeAsync();
        await _postgres.DisposeAsync();
    }

    [Fact]
    public async Task Entries_RoundTripAndVerify()
    {
        for (int i = 0; i < 10; i++)
        {
            await _writer.RecordAsync("test.event", "agent.test", i % 2 == 0 ? "run_a" : null, new { index = i, note = "åäö" }, CancellationToken.None);
        }

        AuditVerificationResult result = await VerifyAsync();

        Assert.True(result.IsValid, result.Failure);
        Assert.Equal(10, result.EntriesChecked);
    }

    [Fact]
    public async Task SchemaSetup_IsIdempotent()
    {
        await _store.EnsureSchemaAsync(CancellationToken.None);
        await _store.EnsureSchemaAsync(CancellationToken.None);
        await _writer.RecordAsync("test.event", "agent.test", null, new { ok = true }, CancellationToken.None);

        Assert.True((await VerifyAsync()).IsValid);
    }

    [Fact]
    public async Task ConcurrentAppends_ProduceContiguousValidChain()
    {
        await Task.WhenAll(Enumerable.Range(0, 50).Select(i =>
            _writer.RecordAsync("test.event", $"agent.worker-{i % 5}", null, new { index = i }, CancellationToken.None)));

        AuditVerificationResult result = await VerifyAsync();

        Assert.True(result.IsValid, result.Failure);
        Assert.Equal(50, result.EntriesChecked);
    }

    [Theory]
    [InlineData("UPDATE audit_log SET payload = '{}' WHERE sequence = 1")]
    [InlineData("DELETE FROM audit_log WHERE sequence = 1")]
    [InlineData("TRUNCATE audit_log")]
    public async Task Mutation_IsRejectedByDatabase(string sql)
    {
        await _writer.RecordAsync("test.event", "agent.test", null, new { index = 1 }, CancellationToken.None);

        var ex = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(sql));

        Assert.Contains("append-only", ex.MessageText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SuperuserTamperingThatBypassesTriggers_IsStillDetected()
    {
        for (int i = 0; i < 5; i++)
        {
            await _writer.RecordAsync("policy.decision", "system.policy-gate", null, new { outcome = "deny", index = i }, CancellationToken.None);
        }

        // Worst case: someone with superuser rights disables the trigger and rewrites history.
        await ExecuteAsync("""
            ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_delete;
            UPDATE audit_log SET payload = '{"index":2,"outcome":"allow"}' WHERE sequence = 3;
            ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update_delete;
            """);

        AuditVerificationResult result = await VerifyAsync();

        Assert.False(result.IsValid);
        Assert.Equal(3, result.FailedAtSequence);
    }

    private Task<AuditVerificationResult> VerifyAsync() =>
        _verifier.VerifyAsync(_store.ReadAllAsync(CancellationToken.None), CancellationToken.None);

    private async Task ExecuteAsync(string sql)
    {
        await using var connection = new NpgsqlConnection(_postgres.GetConnectionString());
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }
}