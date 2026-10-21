using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Lotsen.Audit;

namespace Lotsen.Api.Modules.Governance;

public sealed class ManifestValidationException : Exception
{
    public ManifestValidationException()
        : this(["Agent manifests are invalid."])
    {
    }

    public ManifestValidationException(string message)
        : this([message])
    {
    }

    public ManifestValidationException(string message, Exception innerException)
        : base(message, innerException)
    {
        Errors = [message];
    }

    public ManifestValidationException(IReadOnlyList<string> errors)
        : base("Agent manifests are invalid:" + Environment.NewLine + string.Join(Environment.NewLine, errors.Select(e => " - " + e)))
    {
        Errors = errors;
    }

    public IReadOnlyList<string> Errors { get; }
}

/// <summary>
/// All agent principals, loaded once at startup. Any invalid manifest stops the application:
/// a typo must never silently widen or narrow what an agent can do.
/// </summary>
public sealed partial class AgentRegistry
{
    private static readonly JsonSerializerOptions ManifestOptions = CreateOptions();
    private readonly Dictionary<string, AgentPrincipal> _agents;

    private AgentRegistry(Dictionary<string, AgentPrincipal> agents) => _agents = agents;

    public IReadOnlyCollection<AgentPrincipal> All => _agents.Values;

    public bool TryGet(string agentId, [NotNullWhen(true)] out AgentPrincipal? agent) =>
        _agents.TryGetValue(agentId, out agent);

    public static AgentRegistry LoadFromDirectory(string directory, IReadOnlySet<string> knownTools, IReadOnlySet<string> knownSignals)
    {
        if (!Directory.Exists(directory))
        {
            throw new ManifestValidationException($"Manifest directory '{directory}' does not exist.");
        }

        var manifests = Directory
            .GetFiles(directory, "*.json")
            .Order(StringComparer.Ordinal)
            .Select(path => (Source: Path.GetFileName(path), Json: File.ReadAllText(path)));

        return FromJson(manifests, knownTools, knownSignals);
    }

    public static AgentRegistry FromJson(
        IEnumerable<(string Source, string Json)> manifests,
        IReadOnlySet<string> knownTools,
        IReadOnlySet<string> knownSignals)
    {
        ArgumentNullException.ThrowIfNull(manifests);
        var errors = new List<string>();
        var agents = new Dictionary<string, AgentPrincipal>(StringComparer.Ordinal);

        foreach (var (source, json) in manifests)
        {
            AgentManifest? manifest;
            try
            {
                manifest = JsonSerializer.Deserialize<AgentManifest>(json, ManifestOptions);
            }
            catch (JsonException ex)
            {
                errors.Add($"{source}: {ex.Message}");
                continue;
            }

            if (manifest is null)
            {
                errors.Add($"{source}: manifest is empty.");
                continue;
            }

            var problems = Validate(manifest, knownTools, knownSignals);
            if (problems.Count > 0)
            {
                errors.AddRange(problems.Select(p => $"{source}: {p}"));
                continue;
            }

            if (!agents.TryAdd(manifest.AgentId, new AgentPrincipal(manifest, ComputeHash(json), source)))
            {
                errors.Add($"{source}: duplicate agentId '{manifest.AgentId}'.");
            }
        }

        if (errors.Count == 0 && agents.Count == 0)
        {
            errors.Add("No agent manifests were found.");
        }

        if (errors.Count > 0)
        {
            throw new ManifestValidationException(errors);
        }

        return new AgentRegistry(agents);
    }

    /// <summary>Hash of the canonical form, so formatting changes do not change the policy identity.</summary>
    public static string ComputeHash(string json) =>
        "sha256:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalJson.Canonicalize(json))));

    private static List<string> Validate(AgentManifest m, IReadOnlySet<string> knownTools, IReadOnlySet<string> knownSignals)
    {
        var problems = new List<string>();

        if (m.SchemaVersion != 1)
        {
            problems.Add($"schemaVersion must be 1, was {m.SchemaVersion}.");
        }

        if (!AgentIdPattern().IsMatch(m.AgentId))
        {
            problems.Add($"agentId '{m.AgentId}' must look like 'agent.name-with-dashes'.");
        }

        if (string.IsNullOrWhiteSpace(m.Name) || m.Name.Length > 100)
        {
            problems.Add("name is required and must be at most 100 characters.");
        }

        if (!OwnerIdPattern().IsMatch(m.Owner.Id) || string.IsNullOrWhiteSpace(m.Owner.Name))
        {
            problems.Add("owner must have an id like 'user.name' and a name.");
        }

        foreach (string? tool in m.Tools)
        {
            if (string.IsNullOrWhiteSpace(tool) || !knownTools.Contains(tool))
            {
                problems.Add($"tool '{tool}' is not a registered tool.");
            }
        }

        if (m.Tools.Distinct(StringComparer.Ordinal).Count() != m.Tools.Count)
        {
            problems.Add("tools contains duplicates.");
        }

        if (m.DataScope.Vehicles.Count == 0)
        {
            problems.Add("dataScope.vehicles must list at least one vehicle id or '*'.");
        }

        foreach (string? vehicle in m.DataScope.Vehicles)
        {
            if (vehicle != DataScope.Wildcard && (vehicle is null || !VehicleIdPattern().IsMatch(vehicle)))
            {
                problems.Add($"vehicle '{vehicle}' must be '*' or look like 'VH-001'.");
            }
        }

        if (m.DataScope.Signals.Count == 0)
        {
            problems.Add("dataScope.signals must list at least one signal or '*'.");
        }

        foreach (string? signal in m.DataScope.Signals)
        {
            if (signal != DataScope.Wildcard && (signal is null || !knownSignals.Contains(signal)))
            {
                problems.Add($"signal '{signal}' is not a known telemetry signal.");
            }
        }

        if (m.Budget.MaxTokensPerDay <= 0)
        {
            problems.Add("budget.maxTokensPerDay must be greater than zero.");
        }

        if (m.Budget.MaxCostPerDayUsd <= 0 || m.Budget.MaxCostPerDayUsd > 1000)
        {
            problems.Add("budget.maxCostPerDayUsd must be between 0 and 1000.");
        }

        return problems;
    }

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = false,

            // Strict parsing: unknown fields, missing fields and nulls are errors, not defaults.
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            RespectRequiredConstructorParameters = true,
            RespectNullableAnnotations = true,
            AllowTrailingCommas = false,
            ReadCommentHandling = JsonCommentHandling.Disallow,
        };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.KebabCaseLower, allowIntegerValues: false));
        return options;
    }

    [GeneratedRegex("^agent\\.[a-z0-9]+(-[a-z0-9]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex AgentIdPattern();

    [GeneratedRegex("^user\\.[a-z0-9]+(-[a-z0-9]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex OwnerIdPattern();

    [GeneratedRegex("^VH-[0-9]{3}$", RegexOptions.CultureInvariant)]
    private static partial Regex VehicleIdPattern();
}
