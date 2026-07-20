using Microsoft.AspNetCore.Http;

namespace TikTokProxyHunter.Echo;

public static class EchoAddressResolver
{
    public static string? Resolve(HttpContext context) => context.Connection.RemoteIpAddress?.ToString();
}
