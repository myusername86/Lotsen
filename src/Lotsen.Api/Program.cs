using System.Text.Json;
using System.Text.Json.Serialization;
using Lotsen.Api.Modules.Audit;
using Lotsen.Api.Modules.Governance;
using Lotsen.Api.Modules.Maintenance;
using Lotsen.Api.Modules.Telemetry;

var builder = WebApplication.CreateBuilder(args);

builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.KebabCaseLower)));
builder.Services.AddProblemDetails();
builder.Services.AddHealthChecks();
builder.Services.AddSingleton(TimeProvider.System);

// Vertical slices. Each module registers its own services and endpoints.
builder.AddAuditModule();
builder.AddGovernanceModule();
builder.AddTelemetryModule();
builder.AddMaintenanceModule();

var app = builder.Build();

app.UseExceptionHandler();
app.UseStatusCodePages();
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;
    headers["X-Content-Type-Options"] = "nosniff";
    headers["X-Frame-Options"] = "DENY";
    headers["Referrer-Policy"] = "no-referrer";
    await next(context);
});

// Fail closed: the app refuses to start with a missing signing key or an invalid manifest.
await app.InitializeAuditAsync();
await app.InitializeGovernanceAsync();

app.MapHealthChecks("/health");
app.MapAuditEndpoints();
app.MapGovernanceEndpoints();
app.MapTelemetryEndpoints();
app.MapMaintenanceEndpoints();

await app.RunAsync();

/// <summary>Exposed for integration tests with WebApplicationFactory.</summary>
public partial class Program;
