using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Infrastructure;

public sealed class GitHubSourceDiscoveryService(
    IHttpClientFactory clientFactory,
    IEnumerable<IProxyParser> parsers,
    IProxyNormalizer normalizer,
    ISourceContentFingerprintService fingerprints,
    GitHubDiscoveryOptions options,
    ILogger<GitHubSourceDiscoveryService> logger) : IGitHubSourceDiscoveryService
{
    private static readonly string[] Queries =
    [
        "free proxy list", "socks5 proxy list", "http proxy list", "socks4 proxy list",
        "updated proxy list", "proxy list txt", "proxy list json"
    ];
    private static readonly HashSet<string> LikelyNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "http.txt", "https.txt", "socks4.txt", "socks5.txt", "proxies.txt", "proxy.txt",
        "proxies.json", "proxy.json", "proxies.csv", "proxy.csv"
    };

    public async Task<SourceDiscoveryReport> DiscoverAsync(IReadOnlyList<ProxySourceDefinition> knownSources,
        string? tokenEnvironmentVariable, CancellationToken cancellationToken)
    {
        var tokenName = string.IsNullOrWhiteSpace(tokenEnvironmentVariable)
            ? "TIKTOK_PROXY_HUNTER_GITHUB_TOKEN" : tokenEnvironmentVariable;
        var token = Environment.GetEnvironmentVariable(tokenName);
        var repositories = new Dictionary<string, RepositoryInfo>(StringComparer.OrdinalIgnoreCase);
        var results = new List<DiscoveredProxySource>();
        var knownUrls = knownSources.Where(x => x.Url is not null).Select(x => x.Url!).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var fingerprintsSeen = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var remaining = -1;
        DateTimeOffset? reset = null;
        string? stopReason = null;

        foreach (var query in Queries)
        {
            if (repositories.Count >= options.MaximumRepositories) break;
            var response = await SendApiAsync($"search/repositories?q={Uri.EscapeDataString(query)}&sort=updated&order=desc&per_page=10", token, cancellationToken);
            UpdateRateLimit(response, ref remaining, ref reset);
            if (GitHubApiDiagnostics.IsRateLimited(response.StatusCode, remaining))
            {
                stopReason = $"GitHub API rate limit reached; reset at {reset:O}";
                break;
            }
            if (!response.IsSuccessStatusCode) { stopReason = $"GitHub search stopped with HTTP {(int)response.StatusCode}"; break; }
            using var json = JsonDocument.Parse(response.Body, SafeJsonOptions);
            foreach (var item in json.RootElement.GetProperty("items").EnumerateArray())
            {
                var repo = ParseRepository(item);
                repositories.TryAdd(repo.FullName, repo);
                if (repositories.Count >= options.MaximumRepositories) break;
            }
            if (remaining >= 0 && remaining <= options.MinimumRateLimitRemaining)
            {
                stopReason = "GitHub API rate limit reserve reached";
                break;
            }
        }

        foreach (var repository in repositories.Values)
        {
            if (remaining >= 0 && remaining <= options.MinimumRateLimitRemaining) { stopReason = "GitHub API rate limit reserve reached"; break; }
            if (repository.Archived || repository.PushedAt < DateTimeOffset.UtcNow.AddDays(-options.MaximumRepositoryAgeDays))
            {
                results.Add(Rejected(repository, "Repository is archived or stale"));
                continue;
            }

            var readmeResponse = await SendApiAsync($"repos/{repository.FullName}/readme", token, cancellationToken,
                "application/vnd.github.raw+json");
            UpdateRateLimit(readmeResponse, ref remaining, ref reset);
            if (!readmeResponse.IsSuccessStatusCode)
            {
                results.Add(Rejected(repository, "README is unavailable", SourceDiscoveryStatus.Unavailable));
                continue;
            }

            var treeResponse = await SendApiAsync($"repos/{repository.FullName}/git/trees/{Uri.EscapeDataString(repository.DefaultBranch)}?recursive=1",
                token, cancellationToken);
            UpdateRateLimit(treeResponse, ref remaining, ref reset);
            if (!treeResponse.IsSuccessStatusCode)
            {
                results.Add(Rejected(repository, "Repository tree is unavailable", SourceDiscoveryStatus.Unavailable));
                continue;
            }
            using var tree = JsonDocument.Parse(treeResponse.Body, SafeJsonOptions);
            var paths = tree.RootElement.GetProperty("tree").EnumerateArray()
                .Where(x => x.TryGetProperty("type", out var type) && type.GetString() == "blob")
                .Select(x => x.GetProperty("path").GetString()).Where(x => x is not null)
                .Select(x => x!).Where(x => LikelyNames.Contains(Path.GetFileName(x)))
                .Take(options.MaximumFilesPerRepository).ToArray();
            if (paths.Length == 0)
            {
                results.Add(Rejected(repository, "No likely proxy data files were found"));
                continue;
            }

            foreach (var path in paths)
            {
                var rawUrl = BuildRawUrl(repository, path);
                if (knownUrls.Contains(rawUrl))
                {
                    results.Add(Create(repository, path, rawUrl, SourceDiscoveryStatus.Duplicate, "URL already exists in the source catalog"));
                    continue;
                }
                var sample = await DownloadSampleAsync(rawUrl, cancellationToken);
                if (!sample.Success)
                {
                    results.Add(Create(repository, path, rawUrl, sample.Status, sample.Error ?? "Download failed"));
                    continue;
                }
                var format = Path.GetExtension(path).ToLowerInvariant() switch { ".json" => "json", ".csv" => "csv", _ => "text" };
                var protocol = InferProtocol(path);
                var definition = BuildDefinition(repository, path, rawUrl, format, protocol);
                var parser = parsers.FirstOrDefault(x => x.CanParse(format));
                IReadOnlyList<ProxyCandidate> candidates;
                try { candidates = parser?.Parse(definition, sample.Content!) ?? []; }
                catch (Exception ex) when (ex is JsonException or FormatException or InvalidOperationException)
                {
                    results.Add(new DiscoveredProxySource { Definition = definition, Repository = repository.FullName,
                        RepositoryUpdatedAt = repository.PushedAt, Status = SourceDiscoveryStatus.Rejected,
                        Reason = $"Parser rejected content: {GitHubTokenRedactor.Redact(ex.Message, token)}" });
                    continue;
                }
                var valid = candidates.Count(x => normalizer.TryNormalize(x, out _, out _));
                var fingerprint = fingerprints.ComputeSha256(sample.Bytes!);
                if (fingerprintsSeen.TryGetValue(fingerprint, out var duplicate))
                {
                    results.Add(new DiscoveredProxySource { Definition = definition, Repository = repository.FullName,
                        RepositoryUpdatedAt = repository.PushedAt, Status = SourceDiscoveryStatus.Duplicate,
                        Reason = $"Content is identical to {duplicate}", Fingerprint = fingerprint, ValidCandidates = valid });
                    continue;
                }
                fingerprintsSeen[fingerprint] = definition.Name;
                var status = SourceDiscoveryPolicy.Classify(valid, options.MinimumCandidates, repository.License, false);
                var reason = valid < options.MinimumCandidates ? $"Only {valid} valid candidates"
                    : repository.License == "Unknown" ? "Valid data, but license is unknown; keep disabled"
                    : $"{valid} valid candidates; manual review required";
                results.Add(new DiscoveredProxySource { Definition = definition, Repository = repository.FullName,
                    RepositoryUpdatedAt = repository.PushedAt, Status = status, Reason = reason,
                    Fingerprint = fingerprint, ValidCandidates = valid });
            }
        }

        if (!string.IsNullOrEmpty(stopReason)) logger.LogWarning("Source discovery stopped safely: {Reason}", stopReason);
        return new SourceDiscoveryReport { Sources = results, GitHubRateLimitRemaining = Math.Max(0, remaining),
            GitHubRateLimitReset = reset, StopReason = stopReason };
    }

    private async Task<ApiResponse> SendApiAsync(string relative, string? token, CancellationToken ct, string accept = "application/vnd.github+json")
    {
        var client = clientFactory.CreateClient("github-discovery");
        using var request = new HttpRequestMessage(HttpMethod.Get, relative);
        request.Headers.Accept.ParseAdd(accept);
        request.Headers.Add("X-GitHub-Api-Version", "2022-11-28");
        if (!string.IsNullOrWhiteSpace(token)) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        var body = await ReadLimitedStringAsync(response.Content, Math.Max(options.MaximumSampleBytes, 5_242_880), ct);
        return new ApiResponse(response.StatusCode, body,
            HeaderInt(response.Headers, "X-RateLimit-Remaining"), HeaderDate(response.Headers, "X-RateLimit-Reset"));
    }

    private async Task<SampleResult> DownloadSampleAsync(string url, CancellationToken ct)
    {
        try
        {
            var client = clientFactory.CreateClient("github-raw-discovery");
            using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode) return new(false, null, null, SourceDiscoveryStatus.Unavailable, $"HTTP {(int)response.StatusCode}");
            if (response.Content.Headers.ContentLength > options.MaximumSampleBytes)
                return new(false, null, null, SourceDiscoveryStatus.Suspicious, "File exceeds discovery sample limit");
            var bytes = await ReadLimitedBytesAsync(response.Content, options.MaximumSampleBytes, ct);
            if (bytes.Any(x => x == 0)) return new(false, null, null, SourceDiscoveryStatus.Suspicious, "Binary content detected");
            return new(true, Encoding.UTF8.GetString(bytes), bytes, SourceDiscoveryStatus.Candidate, null);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or OperationCanceledException)
        {
            return new(false, null, null, SourceDiscoveryStatus.Unavailable, ex is OperationCanceledException ? "Timeout" : ex.Message);
        }
    }

    private static async Task<string> ReadLimitedStringAsync(HttpContent content, int max, CancellationToken ct) =>
        Encoding.UTF8.GetString(await ReadLimitedBytesAsync(content, max, ct));

    private static async Task<byte[]> ReadLimitedBytesAsync(HttpContent content, int max, CancellationToken ct)
    {
        await using var input = await content.ReadAsStreamAsync(ct);
        await using var output = new MemoryStream(Math.Min(max, 65_536));
        var buffer = new byte[16_384];
        while (output.Length < max)
        {
            var read = await input.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, max - output.Length)), ct);
            if (read == 0) break;
            await output.WriteAsync(buffer.AsMemory(0, read), ct);
        }
        return output.ToArray();
    }

    private static RepositoryInfo ParseRepository(JsonElement item) => new(item.GetProperty("full_name").GetString()!,
        item.GetProperty("default_branch").GetString()!, item.GetProperty("pushed_at").GetDateTimeOffset(),
        item.GetProperty("archived").GetBoolean(), item.TryGetProperty("license", out var license) && license.ValueKind == JsonValueKind.Object
            && license.TryGetProperty("spdx_id", out var spdx) ? spdx.GetString() ?? "Unknown" : "Unknown");

    private static ProxyProtocol InferProtocol(string path)
    {
        var name = Path.GetFileNameWithoutExtension(path);
        if (name.Contains("socks5", StringComparison.OrdinalIgnoreCase)) return ProxyProtocol.Socks5;
        if (name.Contains("socks4", StringComparison.OrdinalIgnoreCase)) return ProxyProtocol.Socks4;
        if (name.Equals("https", StringComparison.OrdinalIgnoreCase)) return ProxyProtocol.HttpsConnect;
        if (name.Contains("http", StringComparison.OrdinalIgnoreCase)) return ProxyProtocol.Http;
        return ProxyProtocol.Unknown;
    }

    private static ProxySourceDefinition BuildDefinition(RepositoryInfo repo, string path, string rawUrl, string format, ProxyProtocol protocol) => new()
    {
        Name = $"github-{repo.FullName.Replace('/', '-').ToLowerInvariant()}-{Path.GetFileNameWithoutExtension(path).ToLowerInvariant()}",
        Enabled = false, Url = rawUrl, Format = format, DeclaredProtocol = protocol, Category = "GitHubRaw",
        Priority = 25, TrustWeight = 0.25, License = repo.License, Homepage = $"https://github.com/{repo.FullName}",
        ExpectedContentType = format == "json" ? "application/json" : "text/plain", MaximumDownloadBytes = 52_428_800,
        MinimumExpectedCandidates = 10, SourceFamily = repo.FullName, Notes = "Automatically discovered; requires manual review"
    };

    private static DiscoveredProxySource Create(RepositoryInfo repo, string path, string url, SourceDiscoveryStatus status, string reason) => new()
    { Definition = BuildDefinition(repo, path, url, Path.GetExtension(path).ToLowerInvariant() switch { ".json" => "json", ".csv" => "csv", _ => "text" }, InferProtocol(path)), Repository = repo.FullName,
        RepositoryUpdatedAt = repo.PushedAt, Status = status, Reason = reason };

    private static DiscoveredProxySource Rejected(RepositoryInfo repo, string reason, SourceDiscoveryStatus status = SourceDiscoveryStatus.Rejected) =>
        Create(repo, "proxies.txt", BuildRawUrl(repo, "proxies.txt"), status, reason);
    private static string BuildRawUrl(RepositoryInfo repo, string path) =>
        $"https://raw.githubusercontent.com/{repo.FullName}/{Uri.EscapeDataString(repo.DefaultBranch)}/{string.Join('/', path.Split('/').Select(Uri.EscapeDataString))}";
    private static void UpdateRateLimit(ApiResponse response, ref int remaining, ref DateTimeOffset? reset)
    { if (response.Remaining is { } value) remaining = value; if (response.Reset is { } time) reset = time; }
    private static int? HeaderInt(HttpResponseHeaders headers, string name) => headers.TryGetValues(name, out var values)
        && int.TryParse(values.FirstOrDefault(), out var value) ? value : null;
    private static DateTimeOffset? HeaderDate(HttpResponseHeaders headers, string name) => headers.TryGetValues(name, out var values)
        && long.TryParse(values.FirstOrDefault(), out var seconds) ? DateTimeOffset.FromUnixTimeSeconds(seconds) : null;
    private static readonly JsonDocumentOptions SafeJsonOptions = new() { MaxDepth = 64 };
    private sealed record RepositoryInfo(string FullName, string DefaultBranch, DateTimeOffset PushedAt, bool Archived, string License);
    private sealed record ApiResponse(HttpStatusCode StatusCode, string Body, int? Remaining, DateTimeOffset? Reset)
    { public bool IsSuccessStatusCode => (int)StatusCode is >= 200 and < 300; }
    private sealed record SampleResult(bool Success, string? Content, byte[]? Bytes, SourceDiscoveryStatus Status, string? Error);
}

public static class GitHubApiDiagnostics
{
    public static bool IsRateLimited(HttpStatusCode statusCode, int remaining) =>
        statusCode == HttpStatusCode.TooManyRequests || (statusCode == HttpStatusCode.Forbidden && remaining == 0);
}

public static class GitHubTokenRedactor
{
    public static string Redact(string value, string? token) => string.IsNullOrEmpty(token)
        ? value : value.Replace(token, "***", StringComparison.Ordinal);
}

public static class SourceDiscoveryPolicy
{
    public static SourceDiscoveryStatus Classify(int validCandidates, int minimumCandidates, string? license, bool duplicate) =>
        duplicate ? SourceDiscoveryStatus.Duplicate
        : validCandidates < minimumCandidates ? SourceDiscoveryStatus.Rejected
        : string.IsNullOrWhiteSpace(license) || license.Equals("Unknown", StringComparison.OrdinalIgnoreCase)
            ? SourceDiscoveryStatus.Candidate : SourceDiscoveryStatus.AcceptedForReview;
}
