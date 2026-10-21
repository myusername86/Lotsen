using System.Runtime.CompilerServices;
using Npgsql;

namespace Lotsen.Audit;

/// <summary>
/// PostgreSQL store with three layers of protection:
/// 1. no update/delete API in code,
/// 2. database triggers that reject UPDATE, DELETE and TRUNCATE,
/// 3. the hash chain and signatures, which expose tampering even by a superuser who disables the triggers.
/// </summary>
public sealed class PostgresAuditStore : IAuditStore, IAsyncDisposable
{
    // Advisory lock id that serializes appends so sequence numbers and links never race.
    private const long ChainLockKey = 0x46_50_41_55_44_49_54;

    private const string Columns =
        "sequence, occurred_at, event_type, actor_id, run_id, payload, previous_hash, hash, signature, key_id";

    private static readonly string[] SchemaStatements =
    [
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            sequence      BIGINT      PRIMARY KEY CHECK (sequence > 0),
            occurred_at   TIMESTAMPTZ NOT NULL,
            event_type    TEXT        NOT NULL,
            actor_id      TEXT        NOT NULL,
            run_id        TEXT        NULL,
            payload       TEXT        NOT NULL,
            previous_hash TEXT        NOT NULL CHECK (length(previous_hash) = 64),
            hash          TEXT        NOT NULL UNIQUE CHECK (length(hash) = 64),
            signature     TEXT        NOT NULL,
            key_id        TEXT        NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_audit_log_run_id ON audit_log (run_id) WHERE run_id IS NOT NULL",
        """
        CREATE OR REPLACE FUNCTION audit_log_reject_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'audit_log is append-only: % is not allowed', TG_OP;
        END;
        $$
        """,
        """
        CREATE OR REPLACE TRIGGER audit_log_no_update_delete
        BEFORE UPDATE OR DELETE ON audit_log
        FOR EACH ROW EXECUTE FUNCTION audit_log_reject_mutation()
        """,
        """
        CREATE OR REPLACE TRIGGER audit_log_no_truncate
        BEFORE TRUNCATE ON audit_log
        FOR EACH STATEMENT EXECUTE FUNCTION audit_log_reject_mutation()
        """,
    ];

    private readonly NpgsqlDataSource _dataSource;

    public PostgresAuditStore(string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        _dataSource = NpgsqlDataSource.Create(connectionString);
    }

    /// <summary>Idempotent. Safe to run on every startup.</summary>
    public async Task EnsureSchemaAsync(CancellationToken cancellationToken)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await LockChainAsync(connection, transaction, cancellationToken);

        foreach (string statement in SchemaStatements)
        {
            await using var command = new NpgsqlCommand(statement, connection, transaction);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<AuditEntry> AppendAsync(AuditEntryFactory createEntry, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(createEntry);

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await LockChainAsync(connection, transaction, cancellationToken);

        long lastSequence = 0;
        string previousHash = AuditHasher.GenesisHash;
        await using (var head = new NpgsqlCommand(
            "SELECT sequence, hash FROM audit_log ORDER BY sequence DESC LIMIT 1", connection, transaction))
        await using (var reader = await head.ExecuteReaderAsync(cancellationToken))
        {
            if (await reader.ReadAsync(cancellationToken))
            {
                lastSequence = reader.GetInt64(0);
                previousHash = reader.GetString(1);
            }
        }

        AuditEntry entry = createEntry(lastSequence + 1, previousHash);
        AuditStoreGuards.EnsureExtendsHead(entry, lastSequence + 1, previousHash);

        await using (var insert = new NpgsqlCommand(
            $"INSERT INTO audit_log ({Columns}) VALUES (@sequence, @occurred_at, @event_type, @actor_id, @run_id, @payload, @previous_hash, @hash, @signature, @key_id)",
            connection,
            transaction))
        {
            insert.Parameters.AddWithValue("sequence", entry.Sequence);
            insert.Parameters.AddWithValue("occurred_at", entry.OccurredAt);
            insert.Parameters.AddWithValue("event_type", entry.EventType);
            insert.Parameters.AddWithValue("actor_id", entry.ActorId);
            insert.Parameters.AddWithValue("run_id", (object?)entry.RunId ?? DBNull.Value);
            insert.Parameters.AddWithValue("payload", entry.Payload);
            insert.Parameters.AddWithValue("previous_hash", entry.PreviousHash);
            insert.Parameters.AddWithValue("hash", entry.Hash);
            insert.Parameters.AddWithValue("signature", entry.Signature);
            insert.Parameters.AddWithValue("key_id", entry.KeyId);
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return entry;
    }

    public async Task<IReadOnlyList<AuditEntry>> ReadPageAsync(long afterSequence, int take, CancellationToken cancellationToken)
    {
        await using var command = _dataSource.CreateCommand(
            $"SELECT {Columns} FROM audit_log WHERE sequence > @after ORDER BY sequence LIMIT @take");
        command.Parameters.AddWithValue("after", afterSequence);
        command.Parameters.AddWithValue("take", take);

        var entries = new List<AuditEntry>(take);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            entries.Add(Map(reader));
        }

        return entries;
    }

    public async IAsyncEnumerable<AuditEntry> ReadAllAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await using var command = _dataSource.CreateCommand($"SELECT {Columns} FROM audit_log ORDER BY sequence");
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            yield return Map(reader);
        }
    }

    public ValueTask DisposeAsync() => _dataSource.DisposeAsync();

    private static async Task LockChainAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("SELECT pg_advisory_xact_lock(@key)", connection, transaction);
        command.Parameters.AddWithValue("key", ChainLockKey);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static AuditEntry Map(NpgsqlDataReader reader) => new(
        Sequence: reader.GetInt64(0),
        OccurredAt: reader.GetFieldValue<DateTimeOffset>(1),
        EventType: reader.GetString(2),
        ActorId: reader.GetString(3),
        RunId: reader.IsDBNull(4) ? null : reader.GetString(4),
        Payload: reader.GetString(5),
        PreviousHash: reader.GetString(6),
        Hash: reader.GetString(7),
        Signature: reader.GetString(8),
        KeyId: reader.GetString(9));
}
