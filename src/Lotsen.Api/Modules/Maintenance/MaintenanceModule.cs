using Lotsen.Api.Modules.Governance;

namespace Lotsen.Api.Modules.Maintenance;

public static class MaintenanceModule
{
    public static WebApplicationBuilder AddMaintenanceModule(this WebApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddSingleton<MaintenanceTicketStore>();
        builder.Services.AddSingleton<IAgentTool, CreateMaintenanceTicketTool>();
        return builder;
    }

    public static IEndpointRouteBuilder MapMaintenanceEndpoints(this IEndpointRouteBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        app.MapGet("/api/maintenance/tickets", (MaintenanceTicketStore store) => store.All).WithTags("Maintenance");
        return app;
    }
}
