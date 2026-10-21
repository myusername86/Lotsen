using Lotsen.Api.Modules.Governance;

namespace Lotsen.Api.Modules.Telemetry;

public static class TelemetryModule
{
    public static WebApplicationBuilder AddTelemetryModule(this WebApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddSingleton<SyntheticFleet>();
        builder.Services.AddSingleton<IAgentTool, GetVehicleStatusTool>();
        return builder;
    }

    public static IEndpointRouteBuilder MapTelemetryEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Human-facing read endpoint for the dashboard. Agents never call this; they go through the policy gate.
        app.MapGet("/api/vehicles", (SyntheticFleet fleet) => fleet.All).WithTags("Telemetry");
        return app;
    }
}
