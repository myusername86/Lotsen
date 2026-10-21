using System.Text.Json;
using System.Text.Json.Serialization;

namespace Lotsen.Audit;

/// <summary>The only component that creates audit entries: canonicalize, hash, sign, append.</summary>
public sealed class AuditWriter(IAuditStore store, IAuditSigner signer, TimeProvider timeProvider)
{
    public static JsonSerializerOptions PayloadSerializerOptions { get; } = CreateOptions();

    public Task<AuditEntry> RecordAsync<TPayload>(
        string eventType,
        string actorId,
        string? runId,
        TPayload payload,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventType);
        ArgumentException.ThrowIfNullOrWhiteSpace(actorId);

        string canonicalPayload = CanonicalJson.Canonicalize(
            JsonSerializer.SerializeToElement(payload, PayloadSerializerOptions));

        return store.AppendAsync(
            (sequence, previousHash) =>
            {
                // Taken inside the store's lock, so timestamps follow sequence order.
                DateTimeOffset occurredAt = AuditHasher.NormalizeTimestamp(timeProvider.GetUtcNow());
                string hash = AuditHasher.ComputeHash(
                    sequence, occurredAt, eventType, actorId, runId, canonicalPayload, previousHash);
                string signature = Convert.ToBase64String(signer.Sign(Convert.FromHexString(hash)));

                return new AuditEntry(
                    sequence, occurredAt, eventType, actorId, runId, canonicalPayload, previousHash, hash, signature, signer.KeyId);
            },
            cancellationToken);
    }

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.KebabCaseLower));
        return options;
    }
}
