using System.Runtime.CompilerServices;

namespace Lotsen.Audit;

/// <summary>For unit tests and the eval runner. Same contract as the PostgreSQL store.</summary>
public sealed class InMemoryAuditStore : IAuditStore, IDisposable
{
    private readonly List<AuditEntry> _entries = [];
    private readonly SemaphoreSlim _lock = new(1, 1);

    public async Task<AuditEntry> AppendAsync(AuditEntryFactory createEntry, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(createEntry);
        await _lock.WaitAsync(cancellationToken);
        try
        {
            long nextSequence = _entries.Count + 1;
            string previousHash = _entries.Count == 0 ? AuditHasher.GenesisHash : _entries[^1].Hash;
            AuditEntry entry = createEntry(nextSequence, previousHash);
            AuditStoreGuards.EnsureExtendsHead(entry, nextSequence, previousHash);
            _entries.Add(entry);
            return entry;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<IReadOnlyList<AuditEntry>> ReadPageAsync(long afterSequence, int take, CancellationToken cancellationToken)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            return _entries.Where(e => e.Sequence > afterSequence).Take(take).ToList();
        }
        finally
        {
            _lock.Release();
        }
    }

    public async IAsyncEnumerable<AuditEntry> ReadAllAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        AuditEntry[] snapshot;
        await _lock.WaitAsync(cancellationToken);
        try
        {
            snapshot = [.. _entries];
        }
        finally
        {
            _lock.Release();
        }

        foreach (AuditEntry entry in snapshot)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return entry;
        }
    }

    public void Dispose() => _lock.Dispose();
}
