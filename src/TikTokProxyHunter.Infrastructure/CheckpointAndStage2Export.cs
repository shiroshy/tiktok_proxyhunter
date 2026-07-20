using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Infrastructure;

public sealed class RunCheckpointStore : IRunCheckpointStore
{
    public async Task<RunCheckpoint?> LoadAsync(string path, CancellationToken cancellationToken)
    {
        if (!File.Exists(path)) return null;
        await using var stream = File.OpenRead(path);
        return await JsonSerializer.DeserializeAsync<RunCheckpoint>(stream, JsonDefaults.Options, cancellationToken);
    }

    public async Task SaveAsync(string path, RunCheckpoint checkpoint, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        await using var stream = File.Create(path);
        await JsonSerializer.SerializeAsync(stream, checkpoint, JsonDefaults.Options, cancellationToken);
    }

    public static string ComputeConfigurationHash(params string[] values) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', values)))).ToLowerInvariant();

    public static bool CanResume(RunCheckpoint? checkpoint, string configurationHash) =>
        checkpoint is not null && checkpoint.ConfigurationHash.Equals(configurationHash, StringComparison.OrdinalIgnoreCase);
}

public sealed class Stage2ResultExporter
{
    public async Task ExportHealthAsync(string output, IReadOnlyList<ProxySourceHealth> health, CancellationToken token)
    {
        Directory.CreateDirectory(output);
        await WriteJsonAsync(Path.Combine(output, "sources-health.json"), health, token);
        var lines = health.Select(x => $"{x.Status,-24} {x.ValidCandidates,8:N0} valid {x.ContentBytes,12:N0} bytes {x.DownloadTime.TotalMilliseconds,8:N0} ms  {x.SourceName}" +
            (x.DuplicateOf is null ? string.Empty : $"  mirror-of={x.DuplicateOf}") + (x.Reason is null ? string.Empty : $"  {x.Reason}"));
        await File.WriteAllLinesAsync(Path.Combine(output, "sources-health.txt"), lines, token);
    }

    public async Task ExportDiscoveryAsync(string output, SourceDiscoveryReport report, CancellationToken token) =>
        await WriteJsonAsync(Path.Combine(output, "source-discovery-report.json"), report, token);

    public async Task ExportFunnelAsync(string output, PipelineFunnel funnel, CancellationToken token)
    {
        Directory.CreateDirectory(output);
        await WriteJsonAsync(Path.Combine(output, "pipeline-funnel.json"), funnel, token);
        var lines = funnel.Stages.Select(x => $"{x.Stage,-26} input={x.InputCount,8:N0} passed={x.PassedCount,8:N0} rejected={x.RejectedCount,8:N0} " +
            $"elapsed={x.Elapsed.TotalSeconds,7:0.0}s median={x.MedianLatencyMs,7:0}ms" +
            (x.TopFailureCategories.Count == 0 ? string.Empty : $" failures=[{string.Join(", ", x.TopFailureCategories.Select(y => $"{y.Key}:{y.Value}"))}]"));
        await File.WriteAllLinesAsync(Path.Combine(output, "pipeline-funnel.txt"), lines, token);
    }

    public async Task ExportCapabilityMatrixAsync(string output, CapabilityMatrix matrix, CancellationToken token)
    {
        Directory.CreateDirectory(output);
        await WriteJsonAsync(Path.Combine(output, "capability-matrix.json"), matrix, token);
        await File.WriteAllLinesAsync(Path.Combine(output, "capability-matrix.txt"),
            matrix.Counts.Select(x => $"{x.Key,-42} {x.Value,8:N0}")
                .Concat(matrix.NotRunReasons.Select(x => $"NotRun/{x.Key,-35} {x.Value,8:N0}")), token);
    }

    public async Task ExportUserListsAsync(string output, IReadOnlyList<ProxyCheckResult> results, GeoOptions geoOptions,
        bool browserVerificationRequired, CancellationToken token)
    {
        Directory.CreateDirectory(output);
        static bool Safe(ProxyCheckResult x) => !x.Endpoint.HasCredentials;
        var recommended = results.Where(x => Safe(x) && GeoPolicy.IsRecommendationEligible(x.Geo, geoOptions)
            && (x.RecommendationClass == ProxyRecommendationClass.Recommended || LegacyRecommended(x, browserVerificationRequired))).ToArray();
        var fullPlayback = results.Where(x => Safe(x) && (x.RecommendationClass is ProxyRecommendationClass.FullPlaybackVerified
            or ProxyRecommendationClass.Recommended || x.BrowserPlayback.OriginalPostPlaybackResult?.Status == BrowserVerificationStatus.Passed)).ToArray();
        var embedPlayback = results.Where(x => Safe(x) && (x.RecommendationClass == ProxyRecommendationClass.EmbedPlaybackVerified
            || x.BrowserPlayback.EmbedPlayerPlaybackResult?.Status == BrowserVerificationStatus.Passed)).ToArray();
        var playback = fullPlayback.Concat(embedPlayback).DistinctBy(x => x.Endpoint.NormalizedKey, StringComparer.OrdinalIgnoreCase).ToArray();
        var pageOnly = results.Where(x => Safe(x) && x.TikTokCapabilities.Any(c => c.Capability == TikTokCapability.TikTokHomepage && c.Status == TikTokCapabilityStatus.Passed)
            && !playback.Any(y => y.Endpoint.NormalizedKey.Equals(x.Endpoint.NormalizedKey, StringComparison.OrdinalIgnoreCase))).ToArray();
        var stablePage = pageOnly.Where(x => (x.TikTokPageStability ?? x.Stability)?.Status == ProxyStabilityStatus.Stable).ToArray();
        var unverified = results.Where(x => Safe(x) && (x.Geo is null || x.Geo.Decision is GeoResolutionDecision.Unknown or GeoResolutionDecision.Conflicting)
            && (x.TechnicalAccess is TechnicalTikTokAccess.Accessible or TechnicalTikTokAccess.AccessibleGeoUnknown
                || x.TikTokCapabilities.Any(c => c.Status == TikTokCapabilityStatus.Passed))).ToArray();
        var rejected = results.Where(x => Safe(x) && x.RecommendationClass == ProxyRecommendationClass.Rejected).ToArray();
        await File.WriteAllLinesAsync(Path.Combine(output, "recommended.txt"), recommended.Select(x => PublicUri(x.Endpoint)), token);
        await File.WriteAllLinesAsync(Path.Combine(output, "full-playback-verified.txt"), fullPlayback.Select(x => PublicUri(x.Endpoint)), token);
        await File.WriteAllLinesAsync(Path.Combine(output, "embed-playback-verified.txt"), embedPlayback.Select(x => PublicUri(x.Endpoint)), token);
        await File.WriteAllLinesAsync(Path.Combine(output, "stable-page-only.txt"), stablePage.Select(x => PublicUri(x.Endpoint)), token);
        await File.WriteAllLinesAsync(Path.Combine(output, "geo-unresolved-but-working.txt"),
            ["# WARNING: exit country is unresolved/conflicting; never mix these endpoints with recommended proxies.", .. unverified.Select(x => PublicUri(x.Endpoint))], token);
        await File.WriteAllLinesAsync(Path.Combine(output, "rejected.txt"), rejected.Select(x => PublicUri(x.Endpoint)), token);
        // Backward-compatible stage 2.1 files.
        await File.WriteAllLinesAsync(Path.Combine(output, "playback-verified.txt"), playback.Select(x => PublicUri(x.Endpoint)), token);
        await File.WriteAllLinesAsync(Path.Combine(output, "page-only.txt"), pageOnly.Select(x => PublicUri(x.Endpoint)), token);
        await File.WriteAllLinesAsync(Path.Combine(output, "unverified-country.txt"),
            ["# WARNING: country is unknown or conflicting; these proxies are not recommended.", .. unverified.Select(x => PublicUri(x.Endpoint))], token);
        var proxychains = results.Where(x => Safe(x) && x.Endpoint.DetectedProtocol is ProxyProtocol.Socks4 or ProxyProtocol.Socks4a or ProxyProtocol.Socks5)
            .Select(x => $"{(x.Endpoint.DetectedProtocol == ProxyProtocol.Socks5 ? "socks5" : "socks4")} {x.Endpoint.Host} {x.Endpoint.Port}");
        await File.WriteAllLinesAsync(Path.Combine(output, "proxychains.conf"), ["strict_chain", "proxy_dns", "[ProxyList]", .. proxychains], token);
        await File.WriteAllTextAsync(Path.Combine(output, "browser-instructions.txt"), """
Configure a temporary clean browser profile with one proxy from the selected list. Do not change system proxy settings automatically.

Free proxies can read unencrypted HTTP traffic. Never enter passwords or tokens through an untrusted proxy. Do not use your primary TikTok account for the first check. A public proxy can stop working at any time. A browser proxy setting may not affect the TikTok mobile application.
""", token);
        await File.WriteAllLinesAsync(Path.Combine(output, "summary.txt"),
            [$"Recommended: {recommended.Length}", $"Playback verified: {playback.Length}", $"Page only: {pageOnly.Length}",
             $"Unverified country: {unverified.Length}", $"Credentials excluded: {results.Count(x => x.Endpoint.HasCredentials)}"], token);
        await File.WriteAllLinesAsync(Path.Combine(output, "verification-summary.txt"),
            results.Where(Safe).OrderByDescending(x => x.Score.Value).SelectMany(VerificationSummary), token);
    }

    public async Task ExportStage2Async(string output, IReadOnlyList<ProxyCheckResult> results,
        IReadOnlyList<ProxySourceHealth> health, RunCheckpoint checkpoint, CancellationToken token)
    {
        Directory.CreateDirectory(output);
        await ExportHealthAsync(output, health, token);
        await WriteJsonLinesAsync(Path.Combine(output, "exit-ip-results.jsonl"),
            results.Where(x => x.ExitIp is not null).Select(x => new { endpoint = Redact(x.Endpoint), result = x.ExitIp }), token);
        await WriteJsonLinesAsync(Path.Combine(output, "geo-results.jsonl"),
            results.Where(x => x.Geo is not null).Select(x => new { endpoint = Redact(x.Endpoint), result = x.Geo }), token);
        await WriteJsonLinesAsync(Path.Combine(output, "tiktok-capabilities.jsonl"),
            results.Select(x => new { endpoint = Redact(x.Endpoint), capabilities = x.TikTokCapabilities }), token);
        await WriteJsonLinesAsync(Path.Combine(output, "stability-results.jsonl"),
            results.Where(x => x.Stability is not null || x.TikTokPageStability is not null || x.PlaybackStability is not null)
                .Select(x => new { endpoint = Redact(x.Endpoint), network = x.NetworkStability,
                    page = x.TikTokPageStability ?? x.Stability, playback = x.PlaybackStability }), token);
        await WriteJsonLinesAsync(Path.Combine(output, "browser-verification.jsonl"),
            results.Where(x => x.BrowserVerification is not null || x.BrowserPlayback.OriginalPostPlaybackResult is not null
                || x.BrowserPlayback.EmbedPlayerPlaybackResult is not null)
                .Select(x => new { endpoint = Redact(x.Endpoint), original = x.BrowserPlayback.OriginalPostPlaybackResult ?? x.BrowserVerification,
                    embed = x.BrowserPlayback.EmbedPlayerPlaybackResult }), token);
        var best = results.Where(x => x.RecommendationClass != ProxyRecommendationClass.Rejected)
            .OrderByDescending(x => x.Score.Value).Select(ToBest).ToArray();
        await WriteJsonAsync(Path.Combine(output, "best-proxies.json"), best, token);
        await File.WriteAllLinesAsync(Path.Combine(output, "recommended-proxies.txt"),
            results.Where(x => x.RecommendationClass == ProxyRecommendationClass.Recommended && !x.Endpoint.HasCredentials)
                .Select(x => PublicUri(x.Endpoint)), token);
        await File.WriteAllLinesAsync(Path.Combine(output, "page-only-proxies.txt"),
            results.Where(x => x.RecommendationClass == ProxyRecommendationClass.PageOnly && !x.Endpoint.HasCredentials)
                .Select(x => PublicUri(x.Endpoint)), token);
        await WriteJsonLinesAsync(Path.Combine(output, "rejected-russian-exits.jsonl"),
            results.Where(x => x.Geo?.Decision is GeoResolutionDecision.ConfirmedRussia or GeoResolutionDecision.LikelyRussia)
                .Select(x => new { endpoint = Redact(x.Endpoint), exitIp = x.ExitIp?.ExitIp, geo = x.Geo }), token);
        await WriteJsonAsync(Path.Combine(output, "run-checkpoint.json"), checkpoint, token);
    }

    private static object ToBest(ProxyCheckResult x) => new
    {
        endpoint = Redact(x.Endpoint), detectedProtocol = x.Endpoint.DetectedProtocol, exitIp = x.ExitIp?.ExitIp,
        country = x.Geo?.CountryCode, asn = x.Geo?.Asn, sourceCount = x.Endpoint.Sources.Count,
        sourceFamilies = x.Endpoint.SourceFamilies, latencyMs = x.Stability?.MedianLatencyMs ?? x.TikTokChecks.FirstOrDefault()?.TotalTime.TotalMilliseconds,
        probe = x.Probe, exitIpResolution = x.ExitIp, geo = x.Geo, preScore = x.PreScore,
        stability = x.Stability, networkStability = x.NetworkStability, tikTokPageStability = x.TikTokPageStability,
        playbackStability = x.PlaybackStability, tikTokChecks = x.TikTokChecks, tikTokCapabilities = x.TikTokCapabilities,
        browserPlayback = x.BrowserVerification, browserPlaybackSet = x.BrowserPlayback, embedPlayerResults = x.EmbedPlayerResults,
        technicalAccess = x.TechnicalAccess, playbackCapability = x.PlaybackCapability,
        recommendationEligibility = x.RecommendationEligibility,
        score = x.Score, recommendationClass = x.RecommendationClass, successfulChecks = x.SuccessfulChecks,
        checkedAt = DateTimeOffset.UtcNow, exitCheckedAt = x.ExitIp?.CheckedAt, geoCheckedAt = x.Geo?.ResolvedAt
    };

    private static ProxyEndpoint Redact(ProxyEndpoint x) => x with { Password = x.Password is null ? null : "***" };
    private static string PublicUri(ProxyEndpoint endpoint)
    {
        var scheme = endpoint.DetectedProtocol switch { ProxyProtocol.Socks5 => "socks5", ProxyProtocol.Socks4 => "socks4", ProxyProtocol.Socks4a => "socks4a", _ => "http" };
        return $"{scheme}://{(endpoint.Host.Contains(':') ? $"[{endpoint.Host}]" : endpoint.Host)}:{endpoint.Port}";
    }
    private static IEnumerable<string> VerificationSummary(ProxyCheckResult result)
    {
        static string Capability(ProxyCheckResult value, TikTokCapability capability, bool optional = false)
        {
            var item = value.TikTokCapabilities.LastOrDefault(x => x.Capability == capability);
            var suffix = optional ? ", optional" : string.Empty;
            return item is null ? $"NotConfigured ({CapabilityNotRunReason.NotConfigured}){suffix}"
                : $"{item.Status}{suffix}" + (string.IsNullOrWhiteSpace(item.Reason) ? string.Empty : $" ({SanitizeReason(item.Reason)})");
        }
        var stability = result.TikTokPageStability ?? result.Stability;
        return
        [
            $"Proxy: {PublicUri(result.Endpoint)}",
            $"Exit country: {result.Geo?.CountryCode ?? "unresolved"}",
            $"Geo confidence: {result.Geo?.ConfidenceLevel ?? GeoConfidenceLevel.Unknown}",
            $"Homepage: {Capability(result, TikTokCapability.TikTokHomepage)}",
            $"Mobile: {Capability(result, TikTokCapability.TikTokMobilePage, true)}",
            $"Post page: {Capability(result, TikTokCapability.TikTokPostPage)}",
            $"Embed player: {Capability(result, TikTokCapability.TikTokEmbedPlayer)}",
            $"Embed playback: {result.BrowserPlayback.EmbedPlayerPlaybackResult?.Status.ToString() ?? $"NotConfigured ({CapabilityNotRunReason.NotConfigured})"}",
            $"Original playback: {result.BrowserPlayback.OriginalPostPlaybackResult?.Status.ToString() ?? $"NotConfigured ({CapabilityNotRunReason.NotConfigured})"}",
            $"Stability: {(stability is null ? $"NotConfigured ({CapabilityNotRunReason.NotEligible})" : $"{stability.Attempts.Count(x => x.Success)}/{stability.Attempts.Count}")}",
            $"Latency: {(stability?.MedianLatencyMs.ToString("0") ?? "unknown")} ms",
            $"Class: {result.RecommendationClass}",
            $"Last checked: {LatestCheck(result):O}",
            string.Empty
        ];
    }

    private static bool LegacyRecommended(ProxyCheckResult result, bool browserVerificationRequired) =>
        result.RecommendationClass == ProxyRecommendationClass.Rejected
        && result.Stability?.Status == ProxyStabilityStatus.Stable
        && result.TikTokCapabilities.Any(x => x.Capability == TikTokCapability.TikTokDnsAndTunnel && x.Status == TikTokCapabilityStatus.Passed)
        && result.TikTokCapabilities.Any(x => x.Capability == TikTokCapability.TikTokPublicVideoPage && x.Status == TikTokCapabilityStatus.Passed)
        && !result.TikTokCapabilities.Any(x => x.Status == TikTokCapabilityStatus.Challenge)
        && (!browserVerificationRequired || result.BrowserVerification?.Status == BrowserVerificationStatus.Passed);

    private static DateTimeOffset LatestCheck(ProxyCheckResult result) =>
        result.TikTokCapabilities.Select(x => x.CheckedAt)
            .Append(result.Probe?.CheckedAt ?? DateTimeOffset.MinValue)
            .Append(result.ExitIp?.CheckedAt ?? DateTimeOffset.MinValue)
            .Append(result.BrowserVerification?.CheckedAt ?? DateTimeOffset.MinValue).Max();

    private static string SanitizeReason(string reason)
    {
        var query = reason.IndexOf('?');
        return query < 0 ? reason.ReplaceLineEndings(" ") : reason[..query].ReplaceLineEndings(" ") + "?[redacted]";
    }
    private static async Task WriteJsonAsync<T>(string path, T value, CancellationToken token)
    { await using var stream = File.Create(path); await JsonSerializer.SerializeAsync(stream, value, JsonDefaults.Options, token); }
    private static async Task WriteJsonLinesAsync<T>(string path, IEnumerable<T> values, CancellationToken token)
    {
        await using var writer = new StreamWriter(File.Create(path), new UTF8Encoding(false));
        foreach (var value in values) await writer.WriteLineAsync(JsonSerializer.Serialize(value, JsonDefaults.CompactOptions).AsMemory(), token);
    }
}
