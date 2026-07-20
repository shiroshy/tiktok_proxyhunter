using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using MaxMind.Db;
using Microsoft.Playwright;
using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Infrastructure;

public sealed class LocalGeoIpProvider(GeoOptions options) : ILocalGeoIpProvider, IDisposable
{
    private readonly ConcurrentDictionary<string, GeoEvidence> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _readerLock = new();
    private Reader? _countryReader;
    private Reader? _asnReader;
    private DateTime _countryModified;
    private DateTime _asnModified;

    public Task<GeoEvidence> ResolveAsync(string ipAddress, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!options.LocalDatabase.Enabled)
            return Task.FromResult(Error("Local MMDB provider disabled"));
        if (!IPAddress.TryParse(ipAddress, out var ip))
            return Task.FromResult(Error("Invalid IP address"));
        return Task.FromResult(_cache.GetOrAdd(ip.ToString(), _ => ResolveCore(ip)));
    }

    public Task<IReadOnlyList<GeoDatabaseValidationResult>> ValidateAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        IReadOnlyList<GeoDatabaseValidationResult> results =
        [Validate("country", options.LocalDatabase.CountryDatabasePath), Validate("asn", options.LocalDatabase.AsnDatabasePath)];
        return Task.FromResult(results);
    }

    private GeoEvidence ResolveCore(IPAddress ip)
    {
        try
        {
            lock (_readerLock)
            {
                RefreshReaders();
                var country = _countryReader?.Find<Dictionary<string, object>>(ip);
                var asn = _asnReader?.Find<Dictionary<string, object>>(ip);
                var code = NestedString(country, "country", "iso_code") ?? NestedString(country, "registered_country", "iso_code");
                var asnNumber = Value(asn, "autonomous_system_number");
                var organization = Value(asn, "autonomous_system_organization");
                return new GeoEvidence
                {
                    Provider = "local-mmdb", CountryCode = code?.ToUpperInvariant(),
                    Asn = asnNumber is null ? null : $"AS{asnNumber}", Organization = organization,
                    TrustWeight = options.LocalDatabase.TrustWeight, RawConfidence = code is null && asnNumber is null ? 0 : 1,
                    ResponseAge = DatabaseAge(), IsError = code is null && asnNumber is null,
                    Error = code is null && asnNumber is null ? "No matching country or ASN record" : null
                };
            }
        }
        catch (Exception ex) when (ex is InvalidDatabaseException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            return Error($"Local MMDB unavailable: {ex.GetType().Name}");
        }
    }

    private void RefreshReaders()
    {
        Refresh(ref _countryReader, ref _countryModified, options.LocalDatabase.CountryDatabasePath);
        Refresh(ref _asnReader, ref _asnModified, options.LocalDatabase.AsnDatabasePath);
    }

    private static void Refresh(ref Reader? reader, ref DateTime modified, string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) { reader?.Dispose(); reader = null; modified = default; return; }
        var current = File.GetLastWriteTimeUtc(path);
        if (reader is not null && current == modified) return;
        reader?.Dispose(); reader = new Reader(path, FileAccessMode.Memory); modified = current;
    }

    private GeoDatabaseValidationResult Validate(string type, string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return new() { DatabaseType = type, Path = path, Exists = false, Reason = "File not configured or not found" };
        var modified = File.GetLastWriteTimeUtc(path);
        try
        {
            using var reader = new Reader(path, FileAccessMode.Memory);
            var successful = new[] { "1.1.1.1", "8.8.8.8", "2001:4860:4860::8888" }
                .Count(value => reader.Find<Dictionary<string, object>>(IPAddress.Parse(value)) is not null);
            return new() { Success = true, DatabaseType = type, Path = path, Exists = true, FormatValid = true,
                LastModified = modified, Age = DateTimeOffset.UtcNow - modified, SuccessfulTestLookups = successful };
        }
        catch (Exception ex) when (ex is InvalidDatabaseException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            return new() { DatabaseType = type, Path = path, Exists = true, FormatValid = false,
                LastModified = modified, Age = DateTimeOffset.UtcNow - modified, Reason = ex.GetType().Name };
        }
    }

    private TimeSpan? DatabaseAge()
    {
        var dates = new[] { _countryModified, _asnModified }.Where(x => x != default).ToArray();
        return dates.Length == 0 ? null : DateTimeOffset.UtcNow - dates.Max();
    }

    private GeoEvidence Error(string reason) => new() { Provider = "local-mmdb", TrustWeight = options.LocalDatabase.TrustWeight,
        IsError = true, Error = reason, RawConfidence = 0 };
    private static string? Value(Dictionary<string, object>? data, string key) => data?.TryGetValue(key, out var value) == true ? value?.ToString() : null;
    private static string? NestedString(Dictionary<string, object>? data, string parent, string key) =>
        data?.TryGetValue(parent, out var value) == true && value is Dictionary<string, object> nested ? Value(nested, key) : null;

    public void Dispose()
    {
        lock (_readerLock) { _countryReader?.Dispose(); _asnReader?.Dispose(); _countryReader = null; _asnReader = null; }
    }
}

public sealed class ProxyPreScorer(ProxyPreScoreWeights weights) : IProxyPreScorer
{
    public ProxyPreScore Calculate(ProxyCheckResult result)
    {
        var reasons = new List<string>(); var score = 0;
        if (result.Geo?.Decision is GeoResolutionDecision.ConfirmedRussia or GeoResolutionDecision.LikelyRussia)
            return new(0, true, ["Confirmed or likely Russian exit"]);
        Add(result.Endpoint.DetectedProtocol switch
        {
            ProxyProtocol.Socks5 => weights.Socks5, ProxyProtocol.HttpsConnect => weights.HttpConnect,
            ProxyProtocol.Socks4a => weights.Socks4a, ProxyProtocol.Socks4 => weights.Socks4,
            ProxyProtocol.Http => weights.Http, _ => 0
        }, $"Protocol {result.Endpoint.DetectedProtocol}");
        var latency = (result.Probe?.TunnelTime + result.Probe?.ConnectTime)?.TotalMilliseconds ?? double.MaxValue;
        Add(latency switch { < 250 => weights.LatencyBelow250, < 500 => weights.LatencyBelow500,
            < 1000 => weights.LatencyBelow1000, < 2000 => weights.LatencyBelow2000, _ => 0 }, $"Probe latency {latency:0} ms");
        var families = result.Endpoint.SourceFamilies.Count > 0 ? result.Endpoint.SourceFamilies.Distinct(StringComparer.OrdinalIgnoreCase).Count()
            : result.Endpoint.Sources.Distinct(StringComparer.OrdinalIgnoreCase).Count();
        Add(Math.Min(weights.IndependentSourceFamiliesMax, Math.Max(0, families - 1) * 3), $"Independent source families {families}");
        if (result.ExitIp?.Status == ExitIpStatus.Resolved) Add(weights.ExitIpResolved, "Exit IP resolved");
        Add(result.Geo?.Decision switch { GeoResolutionDecision.ConfirmedNonRussia => weights.ConfirmedNonRussia,
            GeoResolutionDecision.LikelyNonRussia => weights.LikelyNonRussia,
            GeoResolutionDecision.Conflicting => -weights.ConflictingGeoPenalty, _ => 0 }, $"Geo {result.Geo?.Decision ?? GeoResolutionDecision.Unknown}");
        return new(Math.Max(0, score), false, reasons);
        void Add(int value, string reason) { if (value == 0) return; score += value; reasons.Add($"{reason}: {value:+#;-#;0}"); }
    }
}

public static class DeterministicPipelineLimiter
{
    public static IReadOnlyList<ProxyCheckResult> Take(IEnumerable<ProxyCheckResult> candidates, int maximum) =>
        candidates.OrderByDescending(x => x.PreScore.Value).ThenBy(x => x.Endpoint.NormalizedKey, StringComparer.OrdinalIgnoreCase)
            .Take(maximum <= 0 ? int.MaxValue : maximum).ToArray();
}

public static class PipelineFunnelBuilder
{
    public static PipelineStageStatistics Create(PipelineStage stage, long input, long passed, TimeSpan elapsed,
        IEnumerable<string>? rejectionReasons = null, IEnumerable<double>? latenciesMs = null)
    {
        var reasons = (rejectionReasons ?? []).GroupBy(x => x).OrderByDescending(x => x.Count()).ThenBy(x => x.Key)
            .ToDictionary(x => x.Key, x => (long)x.Count(), StringComparer.OrdinalIgnoreCase);
        var latencies = (latenciesMs ?? []).Where(x => x >= 0 && double.IsFinite(x)).Order().ToArray();
        return new() { Stage = stage, InputCount = input, PassedCount = passed, RejectedCount = Math.Max(0, input - passed),
            RejectionReasons = reasons, TopFailureCategories = reasons.Take(5).ToArray(), Elapsed = elapsed,
            AverageLatencyMs = latencies.Length == 0 ? 0 : latencies.Average(),
            MedianLatencyMs = latencies.Length == 0 ? 0 : (latencies[(latencies.Length - 1) / 2] + latencies[latencies.Length / 2]) / 2 };
    }
}

public static class TikTokVideoUrlValidator
{
    private static readonly HashSet<string> SensitiveQueryKeys = new(StringComparer.OrdinalIgnoreCase)
    { "token", "access_token", "cookie", "session", "auth", "signature", "secret" };

    public static bool TryValidate(string value, IEnumerable<string> allowedDomains, out Uri? uri, out string? reason)
    {
        uri = null; reason = null;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var candidate) || candidate.Scheme != Uri.UriSchemeHttps)
        { reason = "Only absolute HTTPS URLs are allowed"; return false; }
        if (!allowedDomains.Any(domain => candidate.Host.Equals(domain, StringComparison.OrdinalIgnoreCase)
            || candidate.Host.EndsWith('.' + domain, StringComparison.OrdinalIgnoreCase)))
        { reason = "Host is not an allowed TikTok domain"; return false; }
        if (!candidate.AbsolutePath.Contains("/video/", StringComparison.OrdinalIgnoreCase))
        { reason = "URL is not a public TikTok video page"; return false; }
        var query = System.Web.HttpUtility.ParseQueryString(candidate.Query);
        if (query.AllKeys.Any(key => key is not null && SensitiveQueryKeys.Contains(key)))
        { reason = "URL contains a sensitive query parameter"; return false; }
        uri = candidate; return true;
    }

    public static string SafeDisplay(Uri uri) => uri.GetLeftPart(UriPartial.Path);
}

public static class TikTokVideoFileLoader
{
    public static IReadOnlyList<string> Load(string path) => TikTokVideoConfigLoader.Load(path)
        .Where(x => x.Enabled).Select(x => x.Url).ToArray();
}

public sealed class BrowserDoctor : IBrowserDoctor
{
    public async Task<BrowserDoctorResult> DiagnoseAsync(CancellationToken cancellationToken)
    {
        var script = Path.Combine(AppContext.BaseDirectory, "playwright.ps1");
        var install = $"powershell -ExecutionPolicy Bypass -File \"{script}\" install chromium";
        var before = ChromiumProcesses();
        try
        {
            using var playwright = await Playwright.CreateAsync();
            await using (var browser = await playwright.Chromium.LaunchAsync(new() { Headless = true }))
            {
                await using var context = await browser.NewContextAsync();
                var page = await context.NewPageAsync();
                await page.SetContentAsync("<html><body>browser-doctor</body></html>");
            }
            var httpProxy = await TestProxyConfigurationAsync(playwright.Chromium, "http://127.0.0.1:9");
            var socks5Proxy = await TestProxyConfigurationAsync(playwright.Chromium, "socks5://127.0.0.1:9");
            await Task.Delay(500, cancellationToken);
            var clean = ChromiumProcesses().Except(before).Count() == 0;
            return new() { PackageAvailable = true, ChromiumInstalled = true, LaunchSucceeded = true, CleanShutdown = clean,
                HttpProxyConfigurationSupported = httpProxy, Socks5ProxyConfigurationSupported = socks5Proxy,
                LocalIntegrationTestAvailable = true, InstallCommand = install };
        }
        catch (PlaywrightException ex)
        {
            var missing = ex.Message.Contains("Executable doesn't exist", StringComparison.OrdinalIgnoreCase);
            if (missing) return MissingChromium(install);
            return new() { PackageAvailable = true, ChromiumInstalled = true, InstallCommand = install,
                HttpProxyConfigurationSupported = true, Socks5ProxyConfigurationSupported = true,
                Reason = ex.Message.Split('\n')[0] };
        }
    }

    public static BrowserDoctorResult MissingChromium(string installCommand) => new()
    {
        PackageAvailable = true, ChromiumInstalled = false, LaunchSucceeded = false,
        HttpProxyConfigurationSupported = true, Socks5ProxyConfigurationSupported = true,
        InstallCommand = installCommand, Reason = "Chromium is not installed"
    };

    private static async Task<bool> TestProxyConfigurationAsync(IBrowserType chromium, string proxyServer)
    {
        try
        {
            await using var browser = await chromium.LaunchAsync(new() { Headless = true, Proxy = new Proxy { Server = proxyServer } });
            await using var context = await browser.NewContextAsync();
            var page = await context.NewPageAsync();
            await page.GotoAsync("data:text/html,proxy-doctor");
            return true;
        }
        catch (PlaywrightException) { return false; }
    }

    private static HashSet<int> ChromiumProcesses() => Process.GetProcesses()
        .Where(x => x.ProcessName.Contains("chrome", StringComparison.OrdinalIgnoreCase)
            || x.ProcessName.Contains("chromium", StringComparison.OrdinalIgnoreCase))
        .Select(x => x.Id).ToHashSet();
}

public static class ExplainProxyFormatter
{
    public static string Format(ProxyCheckResult result, GeoOptions options)
    {
        var builder = new System.Text.StringBuilder();
        builder.AppendLine($"Endpoint: {result.Endpoint.Host}:{result.Endpoint.Port}");
        builder.AppendLine($"Protocol: {result.Endpoint.DetectedProtocol}");
        builder.AppendLine(); builder.AppendLine("Network:");
        builder.AppendLine($"  Protocol probe: {(result.Probe?.Success == true ? "Passed" : result.Probe?.FailureReason ?? "NotRun (DependencyUnavailable)")}");
        builder.AppendLine($"  Generic HTTPS: {Status(result, TikTokCapability.ShortGenericHttps)}");
        builder.AppendLine($"  Exit IP: {result.ExitIp?.Status.ToString() ?? "NotRun (DependencyUnavailable)"}{(result.ExitIp?.ExitIp is null ? string.Empty : $" ({result.ExitIp.ExitIp})")}");
        builder.AppendLine($"  Country: {result.Geo?.CountryCode ?? "unknown"}");
        builder.AppendLine($"  Geo confidence: {result.Geo?.ConfidenceLevel ?? GeoConfidenceLevel.Unknown}");
        builder.AppendLine($"  Geo decision: {result.Geo?.Decision ?? GeoResolutionDecision.Unknown}");
        builder.AppendLine("Geo evidence:");
        foreach (var evidence in result.Geo?.Evidence ?? [])
            builder.AppendLine($"  {evidence.Provider}: {evidence.CountryCode ?? (evidence.IsRateLimited ? "rate-limited" : evidence.IsError ? "unavailable" : "unknown")}");
        builder.AppendLine($"Pre-score: {result.PreScore.Value} ({string.Join("; ", result.PreScore.Reasons)})");
        builder.AppendLine(); builder.AppendLine("TikTok capabilities:");
        builder.AppendLine($"  Homepage: {Status(result, TikTokCapability.TikTokHomepage)}");
        builder.AppendLine($"  Mobile page: {Status(result, TikTokCapability.TikTokMobilePage)}");
        builder.AppendLine("  Mobile page is optional (TikTok:MobilePage:RequiredForRecommendation=false) and did not block verification");
        builder.AppendLine($"  Post page: {StatusEither(result, TikTokCapability.TikTokPostPage, TikTokCapability.TikTokPublicVideoPage)}");
        builder.AppendLine($"  oEmbed: {Status(result, TikTokCapability.TikTokOEmbed)}");
        builder.AppendLine($"  Embed player: {Status(result, TikTokCapability.TikTokEmbedPlayer)}");
        builder.AppendLine($"  Embed playback: {BrowserStatus(result.BrowserPlayback.EmbedPlayerPlaybackResult)}");
        builder.AppendLine($"  Original post playback: {BrowserStatus(result.BrowserPlayback.OriginalPostPlaybackResult ?? result.BrowserVerification)}");
        var pageStability = result.TikTokPageStability ?? result.Stability;
        builder.AppendLine(); builder.AppendLine("Stability:");
        builder.AppendLine($"  Page: {(pageStability is null ? "NotRun (NotEligible)" : $"{pageStability.Attempts.Count(x => x.Success)}/{pageStability.Attempts.Count} ({pageStability.Capability})")}");
        builder.AppendLine($"  Playback: {(result.PlaybackStability is null ? "NotRun (NotEligible)" : $"{result.PlaybackStability.Attempts.Count(x => x.Success)}/{result.PlaybackStability.Attempts.Count}")}");
        builder.AppendLine(); builder.AppendLine("Classification:");
        builder.AppendLine($"  Technical access: {result.TechnicalAccess}");
        builder.AppendLine($"  Playback capability: {result.PlaybackCapability}");
        builder.AppendLine($"  Recommendation eligibility: {result.RecommendationEligibility}");
        builder.AppendLine($"  Final class: {result.RecommendationClass}");
        var reasons = NotRecommendedReasons(result, options);
        if (reasons.Count > 0)
        {
            builder.AppendLine("Not Recommended because:");
            foreach (var reason in reasons) builder.AppendLine($"  {reason}");
        }
        return builder.ToString().TrimEnd();
    }

    public static IReadOnlyList<string> NotRecommendedReasons(ProxyCheckResult result, GeoOptions options)
    {
        if (result.RecommendationClass == ProxyRecommendationClass.Recommended) return [];
        var reasons = new List<string>();
        if (!GeoPolicy.IsRecommendationEligible(result.Geo, options))
            reasons.Add($"Geo confidence {result.Geo?.ConfidenceLevel ?? GeoConfidenceLevel.Unknown} is below Geo:MinimumConfidenceForRecommendation={options.MinimumConfidenceForRecommendation}");
        if (result.ExitIp?.Status != ExitIpStatus.Resolved) reasons.Add("Exit IP is not resolved (Recommendation requires ExitIp=Resolved)");
        if ((result.TikTokPageStability ?? result.Stability)?.Status != ProxyStabilityStatus.Stable) reasons.Add("TikTok page stability is not Stable (Stability:MinimumSuccessRatio rule)");
        if (result.PlaybackCapability is not (PlaybackCapability.EmbedPlaybackVerified or PlaybackCapability.FullPlaybackVerified))
            reasons.Add("Playback was not verified (EmbedPlaybackVerified or FullPlaybackVerified is required)");
        if (result.TikTokCapabilities.Any(x => x.Status == TikTokCapabilityStatus.Challenge)) reasons.Add("TikTok challenge was detected");
        if (result.Endpoint.HasCredentials) reasons.Add("Credentials are present; public-list policy forbids authenticated endpoints");
        return reasons;
    }

    private static string Status(ProxyCheckResult result, TikTokCapability capability) =>
        result.TikTokCapabilities.LastOrDefault(x => x.Capability == capability) is { } value
            ? value.Status + (string.IsNullOrWhiteSpace(value.Reason) ? string.Empty : $" ({Safe(value.Reason)})")
            : "NotRun (NotEligible)";

    private static string StatusEither(ProxyCheckResult result, params TikTokCapability[] capabilities)
    {
        var value = result.TikTokCapabilities.LastOrDefault(x => capabilities.Contains(x.Capability));
        return value is null ? "NotRun (NotConfigured)" : value.Status + (string.IsNullOrWhiteSpace(value.Reason) ? string.Empty : $" ({Safe(value.Reason)})");
    }

    private static string BrowserStatus(BrowserVerificationResult? value) => value is null
        ? "NotRun (NotConfigured)" : value.Status + (string.IsNullOrWhiteSpace(value.Reason) ? string.Empty : $" ({Safe(value.Reason)})");

    private static string Safe(string value)
    {
        var query = value.IndexOf('?');
        return (query < 0 ? value : value[..query] + "?[redacted]").ReplaceLineEndings(" ");
    }
}
