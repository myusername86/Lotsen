namespace Lotsen.Api.Modules.Telemetry;

/// <summary>The telemetry signals the platform knows about. Manifests may only reference these.</summary>
public static class VehicleSignals
{
    public const string SpeedKmh = "speed_kmh";
    public const string EngineTempC = "engine_temp_c";
    public const string CoolantLevelPct = "coolant_level_pct";
    public const string OilPressureKpa = "oil_pressure_kpa";
    public const string BatterySocPct = "battery_soc_pct";
    public const string BatteryVoltageV = "battery_voltage_v";
    public const string TyrePressureKpa = "tyre_pressure_kpa";
    public const string FuelLevelPct = "fuel_level_pct";

    public static IReadOnlyList<string> Ordered { get; } =
    [
        SpeedKmh, EngineTempC, CoolantLevelPct, OilPressureKpa, BatterySocPct, BatteryVoltageV, TyrePressureKpa, FuelLevelPct,
    ];

    public static IReadOnlySet<string> All { get; } = Ordered.ToHashSet(StringComparer.Ordinal);
}

public sealed record VehicleSnapshot(string VehicleId, IReadOnlyDictionary<string, double> Signals, DateTimeOffset UpdatedAt);

/// <summary>
/// Synthetic data only: 20 vehicles with fixed-seed values so demos and tests are repeatable.
/// VH-012 runs hot on purpose, for the "why is engine temperature rising" scenario.
/// Replaced by the live simulator and IoT Hub ingestion in a later phase.
/// </summary>
public sealed class SyntheticFleet
{
    public const int VehicleCount = 20;
    private readonly Dictionary<string, VehicleSnapshot> _vehicles = new(StringComparer.Ordinal);

    public SyntheticFleet(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
#pragma warning disable CA5394 // Not security sensitive: fixed seed for repeatable synthetic data.
        var random = new Random(42);
        DateTimeOffset now = timeProvider.GetUtcNow();

        for (int i = 1; i <= VehicleCount; i++)
        {
            string id = $"VH-{i:000}";
            bool runsHot = id == "VH-012";
            var signals = new Dictionary<string, double>(StringComparer.Ordinal)
            {
                [VehicleSignals.SpeedKmh] = Math.Round(40 + (random.NextDouble() * 50), 1),
                [VehicleSignals.EngineTempC] = Math.Round(runsHot ? 112.4 : 85 + (random.NextDouble() * 10), 1),
                [VehicleSignals.CoolantLevelPct] = Math.Round(runsHot ? 41.0 : 75 + (random.NextDouble() * 20), 1),
                [VehicleSignals.OilPressureKpa] = Math.Round(250 + (random.NextDouble() * 100), 1),
                [VehicleSignals.BatterySocPct] = Math.Round(30 + (random.NextDouble() * 65), 1),
                [VehicleSignals.BatteryVoltageV] = Math.Round(12.2 + (random.NextDouble() * 1.8), 2),
                [VehicleSignals.TyrePressureKpa] = Math.Round(620 + (random.NextDouble() * 60), 1),
                [VehicleSignals.FuelLevelPct] = Math.Round(15 + (random.NextDouble() * 80), 1),
            };
#pragma warning restore CA5394
            _vehicles[id] = new VehicleSnapshot(id, signals, now);
        }
    }

    public IEnumerable<VehicleSnapshot> All => _vehicles.Values.OrderBy(v => v.VehicleId, StringComparer.Ordinal);

    public VehicleSnapshot? Find(string vehicleId) => _vehicles.GetValueOrDefault(vehicleId);
}
