namespace Lotsen.Audit;

/// <summary>Builds the next entry once the store has locked the chain head.</summary>
public delegate AuditEntry AuditEntryFactory(long sequence, string previousHash);

/// <summary>
/// Append-only storage. There is deliberately no update or delete method.
/// </summary>
public interface IAuditStore
{
    /// <summary>
    /// Appends atomically: the store locks the head, passes the next sequence and previous hash
    /// to <paramref name="createEntry"/>, then inserts the result.
    /// </summary>
    Task<AuditEntry> AppendAsync(AuditEntryFactory createEntry, CancellationToken cancellationToken);

    Task<IReadOnlyList<AuditEntry>> ReadPageAsync(long afterSequence, int take, CancellationToken cancellationToken);

    IAsyncEnumerable<AuditEntry> ReadAllAsync(CancellationToken cancellationToken);
}

public static class AuditStoreGuards
{
    public static void EnsureExtendsHead(AuditEntry entry, long expectedSequence, string expectedPreviousHash)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (entry.Sequence != expectedSequence || !string.Equals(entry.PreviousHash, expectedPreviousHash, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The new entry does not extend the current chain head.");
        }
    }
}
