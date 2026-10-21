namespace Lotsen.Audit;

/// <summary>
/// One immutable audit record. Each entry stores the hash of the entry before it,
/// its own hash, and an Ed25519 signature over that hash.
/// </summary>
public sealed record AuditEntry(
    long Sequence,
    DateTimeOffset OccurredAt,
    string EventType,
    string ActorId,
    string? RunId,
    string Payload,
    string PreviousHash,
    string Hash,
    string Signature,
    string KeyId);
