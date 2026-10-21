using Lotsen.Audit;

namespace Lotsen.UnitTests;

public sealed class AuditChainTests : IDisposable
{
    private readonly AuditKeyPair _keys = Ed25519Keys.Generate();
    private readonly Ed25519AuditSigner _signer;
    private readonly InMemoryAuditStore _store = new();
    private readonly AuditWriter _writer;
    private readonly AuditVerifier _verifier;

    public AuditChainTests()
    {
        _signer = Ed25519AuditSigner.FromBase64PrivateKey(_keys.PrivateKeyBase64);
        _writer = new AuditWriter(_store, _signer, TimeProvider.System);
        _verifier = new AuditVerifier(new Ed25519SignatureVerifier([_keys.PublicKeyBase64]));
    }

    public void Dispose()
    {
        _signer.Dispose();
        _store.Dispose();
    }

    [Fact]
    public async Task IntactChain_Verifies()
    {
        List<AuditEntry> entries = await WriteChainAsync(5);

        AuditVerificationResult result = await _verifier.VerifyAsync(Stream(entries), CancellationToken.None);

        Assert.True(result.IsValid);
        Assert.Equal(5, result.EntriesChecked);
        Assert.Equal(entries[^1].Hash, result.HeadHash);
    }

    [Fact]
    public async Task EmptyChain_IsValid()
    {
        AuditVerificationResult result = await _verifier.VerifyAsync(Stream([]), CancellationToken.None);

        Assert.True(result.IsValid);
        Assert.Equal(AuditHasher.GenesisHash, result.HeadHash);
    }

    [Fact]
    public async Task EntriesLinkToTheirPredecessor()
    {
        List<AuditEntry> entries = await WriteChainAsync(3);

        Assert.Equal(AuditHasher.GenesisHash, entries[0].PreviousHash);
        Assert.Equal(entries[0].Hash, entries[1].PreviousHash);
        Assert.Equal(entries[1].Hash, entries[2].PreviousHash);
    }

    [Fact]
    public async Task EditedPayload_IsDetected()
    {
        List<AuditEntry> entries = await WriteChainAsync(5);
        entries[2] = entries[2] with { Payload = """{"index":99}""" };

        AuditVerificationResult result = await _verifier.VerifyAsync(Stream(entries), CancellationToken.None);

        Assert.False(result.IsValid);
        Assert.Equal(3, result.FailedAtSequence);
        Assert.Contains("Content modified", result.Failure, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EditedActor_IsDetected()
    {
        List<AuditEntry> entries = await WriteChainAsync(3);
        entries[1] = entries[1] with { ActorId = "user.someone-else" };

        AuditVerificationResult result = await _verifier.VerifyAsync(Stream(entries), CancellationToken.None);

        Assert.False(result.IsValid);
        Assert.Equal(2, result.FailedAtSequence);
    }

    [Fact]
    public async Task DeletedEntry_IsDetected()
    {
        List<AuditEntry> entries = await WriteChainAsync(5);
        entries.RemoveAt(1);

        AuditVerificationResult result = await _verifier.VerifyAsync(Stream(entries), CancellationToken.None);

        Assert.False(result.IsValid);
        Assert.Equal(3, result.FailedAtSequence);
        Assert.Contains("Sequence gap", result.Failure, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReorderedEntries_AreDetected()
    {
        List<AuditEntry> entries = await WriteChainAsync(4);
        (entries[1], entries[2]) = (entries[2], entries[1]);

        AuditVerificationResult result = await _verifier.VerifyAsync(Stream(entries), CancellationToken.None);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task RecomputedHashWithoutPrivateKey_FailsSignatureCheck()
    {
        // An attacker with database access edits the last entry and recomputes its hash.
        // The chain math now looks fine, but they cannot produce a valid signature.
        List<AuditEntry> entries = await WriteChainAsync(3);
        AuditEntry last = entries[^1];
        string forgedPayload = """{"index":"forged"}""";
        string forgedHash = AuditHasher.ComputeHash(
            last.Sequence, last.OccurredAt, last.EventType, last.ActorId, last.RunId, forgedPayload, last.PreviousHash);
        entries[^1] = last with { Payload = forgedPayload, Hash = forgedHash };

        AuditVerificationResult result = await _verifier.VerifyAsync(Stream(entries), CancellationToken.None);

        Assert.False(result.IsValid);
        Assert.Equal(3, result.FailedAtSequence);
        Assert.Contains("signature", result.Failure, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SignedWithUntrustedKey_IsRejected()
    {
        List<AuditEntry> entries = await WriteChainAsync(2);
        var otherVerifier = new AuditVerifier(new Ed25519SignatureVerifier([Ed25519Keys.Generate().PublicKeyBase64]));

        AuditVerificationResult result = await otherVerifier.VerifyAsync(Stream(entries), CancellationToken.None);

        Assert.False(result.IsValid);
        Assert.Equal(1, result.FailedAtSequence);
    }

    [Fact]
    public async Task ConcurrentWrites_ProduceOneValidChain()
    {
        await Task.WhenAll(Enumerable.Range(0, 50).Select(i =>
            _writer.RecordAsync("test.event", "agent.test", "run_concurrent", new { index = i }, CancellationToken.None)));

        AuditVerificationResult result = await _verifier.VerifyAsync(_store.ReadAllAsync(CancellationToken.None), CancellationToken.None);

        Assert.True(result.IsValid);
        Assert.Equal(50, result.EntriesChecked);
    }

    [Fact]
    public void CanonicalJson_IsIndependentOfKeyOrderAndWhitespace()
    {
        Assert.Equal(
            CanonicalJson.Canonicalize("""{ "b": 2, "a": { "y": 1, "x": [3, 2] } }"""),
            CanonicalJson.Canonicalize("""{"a":{"x":[3,2],"y":1},"b":2}"""));
    }

    [Fact]
    public void NormalizedTimestamp_HasMicrosecondPrecision()
    {
        var precise = new DateTimeOffset(2026, 10, 21, 7, 0, 0, TimeSpan.Zero).AddTicks(1_234_567);

        DateTimeOffset normalized = AuditHasher.NormalizeTimestamp(precise);

        Assert.Equal(0, normalized.UtcTicks % 10);
        Assert.Equal(TimeSpan.Zero, normalized.Offset);
    }

    private async Task<List<AuditEntry>> WriteChainAsync(int count)
    {
        for (int i = 0; i < count; i++)
        {
            await _writer.RecordAsync("test.event", "agent.test", "run_1", new { index = i }, CancellationToken.None);
        }

        return [.. await _store.ReadPageAsync(0, 1000, CancellationToken.None)];
    }

    private static async IAsyncEnumerable<AuditEntry> Stream(IEnumerable<AuditEntry> entries)
    {
        foreach (AuditEntry entry in entries)
        {
            yield return entry;
        }

        await Task.CompletedTask;
    }
}
