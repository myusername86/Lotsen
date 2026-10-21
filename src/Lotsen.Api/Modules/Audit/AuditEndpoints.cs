using Lotsen.Audit;

namespace Lotsen.Api.Modules.Audit;

public static class AuditEndpoints
{
    private const int MaxPageSize = 200;

    public static IEndpointRouteBuilder MapAuditEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/audit").WithTags("Audit");

        group.MapGet("/", async (IAuditStore store, long? afterSequence, int? take, CancellationToken ct) =>
        {
            int pageSize = Math.Clamp(take ?? 50, 1, MaxPageSize);
            return Results.Ok(await store.ReadPageAsync(Math.Max(afterSequence ?? 0, 0), pageSize, ct));
        });

        group.MapGet("/verify", async (IAuditStore store, AuditVerifier verifier, CancellationToken ct) =>
            Results.Ok(await verifier.VerifyAsync(store.ReadAllAsync(ct), ct)));

        return app;
    }
}
