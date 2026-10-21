using System.Buffers;
using System.Text;
using System.Text.Json;

namespace Lotsen.Audit;

/// <summary>
/// Produces one deterministic text form for a JSON value: object keys sorted ordinally,
/// no insignificant whitespace. Equal data always hashes to the same value.
/// </summary>
public static class CanonicalJson
{
    public static string Canonicalize(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        using var document = JsonDocument.Parse(json);
        return Canonicalize(document.RootElement);
    }

    public static string Canonicalize(JsonElement element)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            Write(element, writer);
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static void Write(JsonElement element, Utf8JsonWriter writer)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Name);
                    Write(property.Value, writer);
                }

                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    Write(item, writer);
                }

                writer.WriteEndArray();
                break;

            default:
                element.WriteTo(writer);
                break;
        }
    }
}
