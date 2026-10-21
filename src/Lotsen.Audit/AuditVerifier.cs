using System.Text.Json;

namespace Lotsen.Audit;

/// <param name="HeadHash">
/// Hash of the last valid entry. Publish or store it elsewhere periodically: if the newest
/// entries are later cut off, the head hash will no longer match.
/// </param>
public sealed record AuditVerificationResult(
    bool IsValid,
    long EntriesChecked,
    string HeadHash,
    long? FailedAtSequence,
    string? Failure);

/// <summary>Recomputes every hash, link and signature from the first entry to the last.</summary>
public sealed class AuditVerifier(IAuditSignatureVerifier signatures)
{
    public async Task<AuditVerificationResult> VerifyAsync(
        IAsyncEnumerable<AuditEntry> entries, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entries);

        long expectedSequence = 1;
        string previousHash = AuditHasher.GenesisHash;
        long checkedCount = 0;

        await foreach (AuditEntry entry in entries.WithCancellation(cancellationToken))
        {
            string? failure = Check(entry, expectedSequence, previousHash);
            if (failure is not null)
            {
                return new AuditVerificationResult(false, checkedCount, previousHash, entry.Sequence, failure);
            }

            previousHash = entry.Hash;
            expectedSequence++;
            checkedCount++;
        }

        return new AuditVerificationResult(true, checkedCount, previousHash, null, null);
    }

    private string? Check(AuditEntry entry, long expectedSequence, string expectedPreviousHash)
    {
        if (entry.Sequence != expectedSequence)
        {
            return $"Sequence gap: expected {expectedSequence} but found {entry.Sequence}. An entry was removed, inserted or reordered.";
        }

        if (!string.Equals(entry.PreviousHash, expectedPreviousHash, StringComparison.Ordinal))
        {
            return "Broken link: previous hash does not match the prior entry.";
        }

        string canonicalPayload;
        try
        {
            canonicalPayload = CanonicalJson.Canonicalize(entry.Payload);
        }
        catch (JsonException)
        {
            return "Payload is not valid JSON.";
        }

        string recomputed = AuditHasher.ComputeHash(
            entry.Sequence, entry.OccurredAt, entry.EventType, entry.ActorId, entry.RunId, canonicalPayload, entry.PreviousHash);
        if (!string.Equals(recomputed, entry.Hash, StringComparison.Ordinal))
        {
            return "Content modified: recomputed hash does not match the stored hash.";
        }

        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(entry.Signature);
        }
        catch (FormatException)
        {
            return "Signature is not valid Base64.";
        }

        if (!signatures.Verify(entry.KeyId, Convert.FromHexString(entry.Hash), signature))
        {
            return $"Invalid signature or untrusted key '{entry.KeyId}'.";
        }

        return null;
    }
}
