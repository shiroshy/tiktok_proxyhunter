using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using TikTokProxyHunter.Echo;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 1024);
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddFixedWindowLimiter("echo", limiter =>
    {
        limiter.PermitLimit = 30;
        limiter.Window = TimeSpan.FromMinutes(1);
        limiter.QueueLimit = 0;
        limiter.AutoReplenishment = true;
    });
});

var app = builder.Build();
app.UseRateLimiter();
app.MapGet("/health", () => Results.Json(new { status = "ok" })).RequireRateLimiting("echo");
app.MapGet("/ip", (HttpContext context) => Results.Json(new { ip = EchoAddressResolver.Resolve(context) }))
    .RequireRateLimiting("echo");
app.Run();

public partial class Program;
