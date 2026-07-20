using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Infrastructure;

public sealed class ResultExporter(ILogger<ResultExporter> logger) : IResultExporter
{
    public async Task ExportAsync(string outputDirectory, IReadOnlyList<ProxyCandidate> candidates,
        IReadOnlyList<ProxyEndpoint> normalized, IReadOnlyList<ProxyCheckResult> checks,
        RunSummary summary, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(outputDirectory);
        await WriteJsonLinesAsync(Path.Combine(outputDirectory, "all-candidates.jsonl"), candidates.Select(Redact), cancellationToken);
        await WriteJsonLinesAsync(Path.Combine(outputDirectory, "normalized.jsonl"), normalized.Select(Redact), cancellationToken);

        var working = checks.Where(x => x.Probe?.Success == true).ToArray();
        await WriteJsonAsync(Path.Combine(outputDirectory, "working-proxies.json"), working.Select(Redact), cancellationToken);
        var accessible = checks.Where(x => x.TikTokChecks.Any(c => c.Status == TikTokStatus.Accessible)).ToArray();
        await WriteJsonAsync(Path.Combine(outputDirectory, "tiktok-accessible.json"), accessible.Select(Redact), cancellationToken);
        await File.WriteAllLinesAsync(Path.Combine(outputDirectory, "tiktok-accessible.txt"),
            accessible.Where(x => !x.Endpoint.HasCredentials).Select(x => ToPublicUri(x.Endpoint)), cancellationToken);

        var failed = checks.Where(x => x.Probe?.Success != true || !x.TikTokChecks.Any(c => c.Status == TikTokStatus.Accessible));
        await WriteJsonLinesAsync(Path.Combine(outputDirectory, "failed.jsonl"), failed.Select(Redact), cancellationToken);
        await WriteJsonAsync(Path.Combine(outputDirectory, "summary.json"), summary, cancellationToken);

        var credentialed = (checks.Count > 0 ? checks.Select(x => x.Endpoint) : normalized)
            .Where(x => x.HasCredentials).DistinctBy(x => x.NormalizedKey).ToArray();
        if (credentialed.Length > 0)
        {
            var privatePath = Path.Combine(outputDirectory, "credentialed-proxies.private.json");
            await WriteJsonAsync(privatePath, credentialed, cancellationToken);
            logger.LogWarning("{Count} authenticated proxies were excluded from TXT. Protect access to {Path}", credentialed.Length, privatePath);
        }
    }

    private static ProxyCandidate Redact(ProxyCandidate x) => x with { Password = x.Password is null ? null : "***", Raw = null };
    private static ProxyEndpoint Redact(ProxyEndpoint x) => x with { Password = x.Password is null ? null : "***" };
    private static ProxyCheckResult Redact(ProxyCheckResult x) => x with { Endpoint = Redact(x.Endpoint), Probe = x.Probe is null ? null : x.Probe with { Endpoint = Redact(x.Probe.Endpoint) } };

    private static string ToPublicUri(ProxyEndpoint endpoint)
    {
        var scheme = endpoint.DetectedProtocol switch
        {
            ProxyProtocol.Socks5 => "socks5", ProxyProtocol.Socks4 => "socks4", ProxyProtocol.Socks4a => "socks4a", _ => "http"
        };
        var host = endpoint.Host.Contains(':', StringComparison.Ordinal) ? $"[{endpoint.Host}]" : endpoint.Host;
        return $"{scheme}://{host}:{endpoint.Port}";
    }

    private static async Task WriteJsonAsync<T>(string path, T value, CancellationToken token)
    {
        await using var stream = File.Create(path);
        await JsonSerializer.SerializeAsync(stream, value, JsonDefaults.Options, token);
    }

    private static async Task WriteJsonLinesAsync<T>(string path, IEnumerable<T> values, CancellationToken token)
    {
        await using var stream = File.Create(path);
        await using var writer = new StreamWriter(stream, new UTF8Encoding(false));
        foreach (var value in values)
        {
            await writer.WriteLineAsync(JsonSerializer.Serialize(value, JsonDefaults.CompactOptions).AsMemory(), token);
        }
    }
}
