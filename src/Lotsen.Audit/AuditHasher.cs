using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace Lotsen.Audit;

/// <summary>
/// Computes the chain hash of an entry. The hash covers every field plus the previous
/// entry's hash, so changing, removing or reordering any entry breaks the chain.
/// </summary>
public static class AuditHasher
{
    /// <summary>Bump only together with a verifier that understands both versions.</summary>
    public const string HashSchemeVersion = "1";

    /// <summary>The "previous hash" of the very first entry.</summary>
    public static readonly string GenesisHash = new('0', 64);

    /// <summary>
    /// PostgreSQL stores timestamps with microsecond precision, .NET with 100 ns ticks.
    /// Truncating before hashing guarantees the value read back from the database hashes identically.
    /// </summary>
    public static DateTimeOffset NormalizeTimestamp(DateTimeOffset value)
    {
        long ticks = value.UtcTicks;
        return new DateTimeOffset(ticks - (ticks % 10), TimeSpan.Zero);
    }

    public static string ComputeHash(
        long sequence,
        DateTimeOffset occurredAt,
        string eventType,
        string actorId,
        string? runId,
        string canonicalPayload,
        string previousHash)
    {
        byte[] input = BuildHashInput(sequence, occurredAt, eventType, actorId, runId, canonicalPayload, previousHash);
        return Convert.ToHexStringLower(SHA256.HashData(input));
    }

    /// <summary>Canonical JSON with keys written in sorted order, so the input is unambiguous.</summary>
    public static byte[] BuildHashInput(
        long sequence,
        DateTimeOffset occurredAt,
        string eventType,
        string actorId,
        string? runId,
        string canonicalPayload,
        string previousHash)
    {
        ArgumentNullException.ThrowIfNull(eventType);
        ArgumentNullException.ThrowIfNull(actorId);
        ArgumentNullException.ThrowIfNull(canonicalPayload);
        ArgumentNullException.ThrowIfNull(previousHash);

        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("actor", actorId);
            writer.WriteString("event", eventType);
            writer.WritePropertyName("payload");
            writer.WriteRawValue(canonicalPayload);
            writer.WriteString("prev", previousHash);
            if (runId is null)
            {
                writer.WriteNull("run");
            }
            else
            {
                writer.WriteString("run", runId);
            }

            writer.WriteNumber("seq", sequence);
            writer.WriteString(
                "ts",
                NormalizeTimestamp(occurredAt).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ", CultureInfo.InvariantCulture));
            writer.WriteString("v", HashSchemeVersion);
            writer.WriteEndObject();
        }

        return buffer.WrittenSpan.ToArray();
    }
}
