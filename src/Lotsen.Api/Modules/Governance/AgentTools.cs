using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Lotsen.Api.Modules.Governance;

public enum ToolEffect
{
    /// <summary>Reads data. Never changes anything.</summary>
    Read,

    /// <summary>Changes state or reaches a person (tickets, alerts, settings).</summary>
    Write,
}

/// <summary>What data a call touches, worked out by code from the actual arguments, never by the model.</summary>
public sealed record ToolScope(IReadOnlyList<string> VehicleIds, IReadOnlyList<string> Signals);

/// <summary>Who is calling. Built by the server, so a model cannot claim another identity.</summary>
public sealed record ToolExecutionContext(string AgentId, string RunId);

/// <summary>
/// A capability an agent may request. Tools never check permissions themselves:
/// the policy gate decides before <see cref="ExecuteAsync"/> is ever called.
/// </summary>
public interface IAgentTool
{
    string Name { get; }

    string Description { get; }

    ToolEffect Effect { get; }

    /// <summary>Validates the arguments strictly and returns the vehicles and signals the call would touch.</summary>
    /// <exception cref="ToolArgumentException">The arguments are malformed or contain unknown fields.</exception>
    ToolScope ResolveScope(JsonElement arguments);

    Task<object> ExecuteAsync(ToolExecutionContext context, JsonElement arguments, CancellationToken cancellationToken);
}

public sealed class ToolArgumentException : Exception
{
    public ToolArgumentException()
    {
    }

    public ToolArgumentException(string message)
        : base(message)
    {
    }

    public ToolArgumentException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public sealed class ToolCatalog
{
    private readonly Dictionary<string, IAgentTool> _tools = new(StringComparer.Ordinal);

    public ToolCatalog(IEnumerable<IAgentTool> tools)
    {
        ArgumentNullException.ThrowIfNull(tools);
        foreach (IAgentTool tool in tools)
        {
            if (!_tools.TryAdd(tool.Name, tool))
            {
                throw new InvalidOperationException($"Tool '{tool.Name}' is registered twice.");
            }
        }

        Names = _tools.Keys.ToHashSet(StringComparer.Ordinal);
    }

    public IReadOnlySet<string> Names { get; }

    public IReadOnlyCollection<IAgentTool> All => _tools.Values;

    public bool TryGet(string name, [NotNullWhen(true)] out IAgentTool? tool) => _tools.TryGetValue(name, out tool);
}

/// <summary>Strict argument parsing shared by tools. Anything unexpected is rejected.</summary>
public static partial class ToolArguments
{
    public static void RequireObject(JsonElement arguments, params string[] allowedProperties)
    {
        ArgumentNullException.ThrowIfNull(allowedProperties);
        if (arguments.ValueKind != JsonValueKind.Object)
        {
            throw new ToolArgumentException("Arguments must be a JSON object.");
        }

        foreach (JsonProperty property in arguments.EnumerateObject())
        {
            if (!allowedProperties.Contains(property.Name, StringComparer.Ordinal))
            {
                throw new ToolArgumentException($"Unknown argument '{Truncate(property.Name)}'.");
            }
        }
    }

    public static string RequireString(JsonElement arguments, string name, int maxLength)
    {
        if (!arguments.TryGetProperty(name, out JsonElement value) || value.ValueKind != JsonValueKind.String)
        {
            throw new ToolArgumentException($"Argument '{name}' is required and must be a string.");
        }

        string text = value.GetString()!;
        if (string.IsNullOrWhiteSpace(text) || text.Length > maxLength)
        {
            throw new ToolArgumentException($"Argument '{name}' must be 1 to {maxLength} characters.");
        }

        return text;
    }

    public static string RequireVehicleId(JsonElement arguments, string name = "vehicleId")
    {
        string vehicleId = RequireString(arguments, name, 16);
        if (!VehicleIdPattern().IsMatch(vehicleId))
        {
            throw new ToolArgumentException($"Argument '{name}' must look like 'VH-001'.");
        }

        return vehicleId;
    }

    public static string RequireOneOf(JsonElement arguments, string name, params string[] allowedValues)
    {
        string value = RequireString(arguments, name, 32);
        if (!allowedValues.Contains(value, StringComparer.Ordinal))
        {
            throw new ToolArgumentException($"Argument '{name}' must be one of: {string.Join(", ", allowedValues)}.");
        }

        return value;
    }

    public static IReadOnlyList<string>? OptionalStringArray(JsonElement arguments, string name, int maxItems)
    {
        if (!arguments.TryGetProperty(name, out JsonElement value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > maxItems)
        {
            throw new ToolArgumentException($"Argument '{name}' must be an array of at most {maxItems} strings.");
        }

        var items = new List<string>();
        foreach (JsonElement item in value.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(item.GetString()))
            {
                throw new ToolArgumentException($"Argument '{name}' must contain only non-empty strings.");
            }

            items.Add(item.GetString()!);
        }

        return items.Distinct(StringComparer.Ordinal).ToList();
    }

    private static string Truncate(string value) => value.Length <= 40 ? value : value[..40] + "...";

    [GeneratedRegex("^VH-[0-9]{3}$", RegexOptions.CultureInvariant)]
    private static partial Regex VehicleIdPattern();
}
