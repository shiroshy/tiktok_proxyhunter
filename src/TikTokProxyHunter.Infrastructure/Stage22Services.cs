using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Infrastructure;

public static partial class TikTokVideoUrlParser
{
    public static bool TryParse(Uri uri, IEnumerable<string> allowedDomains, out string? postId, out Uri? playerUrl, out string? reason)
    {
        postId = null; playerUrl = null; reason = null;
        if (uri.Scheme != Uri.UriSchemeHttps) { reason = "Only HTTPS video URLs are allowed"; return false; }
        if (!allowedDomains.Any(domain => uri.Host.Equals(domain, StringComparison.OrdinalIgnoreCase)
            || uri.Host.EndsWith('.' + domain, StringComparison.OrdinalIgnoreCase)))
        { reason = "Video hostname is not an allowed TikTok domain"; return false; }
        if (!string.IsNullOrEmpty(uri.Query)) { reason = "Video URL query parameters are not allowed"; return false; }
        var match = PostRegex().Match(uri.AbsolutePath);
        if (!match.Success) { reason = "URL does not contain a numeric TikTok post ID"; return false; }
        postId = match.Groups["id"].Value;
        playerUrl = new Uri($"https://www.tiktok.com/player/v1/{postId}");
        return true;
    }

    public static Uri Sanitize(Uri uri) => new(uri.GetLeftPart(UriPartial.Path));

    [GeneratedRegex(@"/(?:@[^/]+/video|v)/(?<id>\d{5,})(?:/|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PostRegex();
}

public static class TikTokVideoConfigLoader
{
    public static IReadOnlyList<TikTokTestVideo> Load(string path)
    {
        if (!File.Exists(path)) return [];
        using var document = JsonDocument.Parse(File.ReadAllText(path), new JsonDocumentOptions { MaxDepth = 16 });
        if (document.RootElement.TryGetProperty("videos", out var videos) && videos.ValueKind == JsonValueKind.Array)
            return videos.Deserialize<List<TikTokTestVideo>>(JsonDefaults.Options) ?? [];
        if (document.RootElement.TryGetProperty("publicVideoTestUrls", out var legacy) && legacy.ValueKind == JsonValueKind.Array)
            return legacy.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String)
                .Select((x, index) => new TikTokTestVideo { Name = $"legacy-{index + 1}", Url = x.GetString()! }).ToArray();
        return [];
    }
}

public sealed class TikTokVideoValidationService(IHttpClientFactory factory, TikTokVerificationOptions options)
{
    public async Task<IReadOnlyList<TikTokVideoValidationResult>> ValidateAsync(string path, CancellationToken cancellationToken)
    {
        if (!File.Exists(path)) return [new() { Name = "configuration", Status = TikTokCapabilityStatus.NotConfigured,
            Reason = "TikTok video configuration file was not found" }];
        IReadOnlyList<TikTokTestVideo> videos;
        try { videos = TikTokVideoConfigLoader.Load(path); }
        catch (JsonException ex) { return [new() { Name = "configuration", Status = TikTokCapabilityStatus.InvalidContent,
            Reason = $"Invalid JSON: {ex.Message}" }]; }
        if (videos.Count == 0) return [new() { Name = "configuration", Status = TikTokCapabilityStatus.NotConfigured,
            Reason = "No videos are configured" }];
        var client = factory.CreateClient("tiktok-video-validation"); var results = new List<TikTokVideoValidationResult>();
        foreach (var video in videos.Where(x => x.Enabled))
        {
            if (!Uri.TryCreate(video.Url, UriKind.Absolute, out var postUrl))
            { results.Add(new() { Name = video.Name, Status = TikTokCapabilityStatus.InvalidContent, Reason = "URL is not an absolute URI." }); continue; }
            if (!TikTokVideoUrlParser.TryParse(postUrl, options.AllowedVideoDomains, out var postId, out var playerUrl, out var reason))
            { results.Add(new() { Name = video.Name, PostUrl = postUrl, Status = TikTokCapabilityStatus.InvalidContent, Reason = reason }); continue; }
            try
            {
                using var player = await client.GetAsync(playerUrl, cancellationToken);
                var playerBody = await player.Content.ReadAsStringAsync(cancellationToken);
                var oembedUrl = $"{options.OEmbedEndpoint}?url={Uri.EscapeDataString(postUrl.AbsoluteUri)}";
                using var oembed = await client.GetAsync(oembedUrl, cancellationToken);
                var oembedBody = await oembed.Content.ReadAsStringAsync(cancellationToken);
                var challenge = HasChallenge(playerBody) || HasChallenge(oembedBody);
                var playerValid = player.IsSuccessStatusCode && options.EmbedPlayerMarkers.Any(x => playerBody.Contains(x, StringComparison.OrdinalIgnoreCase));
                var oembedValid = oembed.IsSuccessStatusCode && TikTokContentClassifier.ClassifyOEmbed((int)oembed.StatusCode, oembedBody, postUrl) == TikTokCapabilityStatus.Passed;
                var suitable = playerValid && oembedValid && !challenge;
                results.Add(new() { Name = video.Name, PostUrl = TikTokVideoUrlParser.Sanitize(postUrl), PostId = postId,
                    PlayerUrl = playerUrl, Status = challenge ? TikTokCapabilityStatus.Challenge
                        : suitable ? TikTokCapabilityStatus.Passed : TikTokCapabilityStatus.InvalidContent,
                    PlayerHttpStatus = (int)player.StatusCode, OEmbedHttpStatus = (int)oembed.StatusCode, Suitable = suitable,
                    Reason = suitable ? null : challenge ? "Challenge in clean direct request" : "Player or oEmbed validation failed" });
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            { results.Add(new() { Name = video.Name, PostUrl = TikTokVideoUrlParser.Sanitize(postUrl), PostId = postId,
                PlayerUrl = playerUrl, Status = TikTokCapabilityStatus.Timeout, Reason = "Direct validation timed out" }); }
            catch (HttpRequestException ex)
            { results.Add(new() { Name = video.Name, PostUrl = TikTokVideoUrlParser.Sanitize(postUrl), PostId = postId,
                PlayerUrl = playerUrl, Status = TikTokCapabilityStatus.Unavailable, Reason = ex.GetType().Name }); }
        }
        return results;
    }

    private static bool HasChallenge(string body) => body.Contains("captcha", StringComparison.OrdinalIgnoreCase)
        || body.Contains("verify you are human", StringComparison.OrdinalIgnoreCase)
        || body.Contains("access denied", StringComparison.OrdinalIgnoreCase);
}

public sealed class TikTokEmbedPlayerVerifier(ProxyHttpsClient proxyClient, TikTokVerificationOptions options) : ITikTokEmbedPlayerVerifier
{
    public async Task<TikTokEmbedPlayerResult> VerifyAsync(ProxyEndpoint endpoint, Uri postUrl, CancellationToken cancellationToken)
    {
        if (!TikTokVideoUrlParser.TryParse(postUrl, options.AllowedVideoDomains, out var postId, out var playerUrl, out var reason))
            return Invalid(postUrl, postId ?? string.Empty, TikTokCapabilityStatus.InvalidContent, reason!);
        var watch = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            var response = await proxyClient.GetAsync(endpoint, playerUrl!, cancellationToken, 2_000_000);
            return TikTokEmbedPlayerClassifier.Classify(postId!, playerUrl!, response.StatusCode, response.Body,
                response.Headers, watch.Elapsed, options.EmbedPlayerMarkers);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { return Invalid(playerUrl!, postId!, TikTokCapabilityStatus.Timeout, "Timeout") with { Latency = watch.Elapsed }; }
        catch (Exception ex) when (ex is IOException or InvalidDataException or HttpRequestException
            or System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException or NotSupportedException)
        { return Invalid(playerUrl!, postId!, TikTokCapabilityStatus.Unavailable, ex.Message) with { Latency = watch.Elapsed }; }
    }

    private static TikTokEmbedPlayerResult Invalid(Uri url, string postId, TikTokCapabilityStatus status, string reason) => new()
    { PostId = postId, RequestedUrl = url, FinalUrl = TikTokVideoUrlParser.Sanitize(url), Status = status, FailureReason = reason };
}

public static class TikTokEmbedPlayerClassifier
{
    public static TikTokEmbedPlayerResult Classify(string postId, Uri requestedUrl, int httpStatus, string body,
        IReadOnlyDictionary<string, string> headers, TimeSpan latency, IEnumerable<string> markers)
    {
        var challenge = body.Contains("captcha", StringComparison.OrdinalIgnoreCase)
            || body.Contains("verify you are human", StringComparison.OrdinalIgnoreCase)
            || body.Contains("cf-chl-", StringComparison.OrdinalIgnoreCase);
        var found = markers.Any(marker => body.Contains(marker, StringComparison.OrdinalIgnoreCase))
            && body.Contains(postId, StringComparison.Ordinal);
        var status = httpStatus == 429 ? TikTokCapabilityStatus.RateLimited
            : httpStatus is 401 or 403 ? TikTokCapabilityStatus.Blocked
            : challenge ? TikTokCapabilityStatus.Challenge
            : httpStatus is < 200 or >= 400 ? TikTokCapabilityStatus.Failed
            : found ? TikTokCapabilityStatus.Passed : TikTokCapabilityStatus.InvalidContent;
        return new() { PostId = postId, RequestedUrl = requestedUrl, FinalUrl = TikTokVideoUrlParser.Sanitize(requestedUrl),
            Status = status, HttpStatus = httpStatus, Latency = latency, ExpectedPlayerMarkersFound = found,
            ChallengeDetected = challenge, FailureReason = status == TikTokCapabilityStatus.Passed ? null : status.ToString() };
    }
}

public static partial class MediaRequestClassifier
{
    public static MediaRequestObservation Classify(Uri uri, int status, string? contentType, string resourceType,
        IReadOnlyDictionary<string, string> headers, IEnumerable<string> mediaDomains)
    {
        var tiktok = uri.Host.Equals("tiktok.com", StringComparison.OrdinalIgnoreCase)
            || uri.Host.EndsWith(".tiktok.com", StringComparison.OrdinalIgnoreCase);
        var mediaHost = mediaDomains.Any(domain => uri.Host.Equals(domain, StringComparison.OrdinalIgnoreCase)
            || uri.Host.EndsWith('.' + domain, StringComparison.OrdinalIgnoreCase));
        var mediaType = contentType?.StartsWith("video/", StringComparison.OrdinalIgnoreCase) == true
            || contentType?.StartsWith("audio/", StringComparison.OrdinalIgnoreCase) == true
            || contentType?.Contains("octet-stream", StringComparison.OrdinalIgnoreCase) == true;
        var category = uri.Host.Contains("analytics", StringComparison.OrdinalIgnoreCase) || uri.AbsolutePath.Contains("pixel", StringComparison.OrdinalIgnoreCase)
            ? MediaRequestCategory.ThirdPartyAnalytics
            : uri.Host.Contains("challenge", StringComparison.OrdinalIgnoreCase) ? MediaRequestCategory.Challenge
            : resourceType.Equals("image", StringComparison.OrdinalIgnoreCase) ? MediaRequestCategory.TikTokImage
            : status is 200 or 206 && (mediaType || mediaHost) && resourceType is "media" or "fetch" ? MediaRequestCategory.TikTokMedia
            : uri.AbsolutePath.Contains("/player/", StringComparison.OrdinalIgnoreCase) ? MediaRequestCategory.TikTokPlayer
            : resourceType.Equals("document", StringComparison.OrdinalIgnoreCase) && tiktok ? MediaRequestCategory.TikTokDocument
            : tiktok && uri.AbsolutePath.Contains("/api/", StringComparison.OrdinalIgnoreCase) ? MediaRequestCategory.TikTokApi
            : MediaRequestCategory.Unknown;
        headers.TryGetValue("content-length", out var lengthText);
        return new() { Host = uri.Host, PathPattern = SanitizePath(uri.AbsolutePath), Category = category,
            Status = status, ContentType = contentType, ResourceType = resourceType,
            ByteRange = status == 206 || headers.ContainsKey("content-range") || headers.ContainsKey("accept-ranges"),
            ContentLength = long.TryParse(lengthText, out var length) ? length : null };
    }

    public static bool IsSuccessfulMedia(MediaRequestObservation item) => item.Status is 200 or 206
        && item.Category == MediaRequestCategory.TikTokMedia;

    public static string SanitizePath(string path) => TokenRegex().Replace(path, "{id}");

    [GeneratedRegex(@"(?<![A-Za-z])[A-Za-z0-9_-]{16,}(?![A-Za-z])", RegexOptions.CultureInvariant)]
    private static partial Regex TokenRegex();
}

public static class ResultFreshness
{
    public static bool ProtocolFresh(ProxyProbeResult? result, ResultTtlOptions ttl, DateTimeOffset now) =>
        result?.Success == true && now - result.CheckedAt <= TimeSpan.FromMinutes(ttl.ProtocolMinutes);
    public static bool ExitFresh(ExitIpResolutionResult? result, ResultTtlOptions ttl, DateTimeOffset now) =>
        result is not null && now - result.CheckedAt <= TimeSpan.FromMinutes(ttl.ExitIpMinutes);
    public static bool GeoFresh(ProxyGeoInfo? result, ResultTtlOptions ttl, DateTimeOffset now) =>
        result is not null && now - result.ResolvedAt <= TimeSpan.FromHours(ttl.GeoHours);
    public static bool CapabilityFresh(TikTokCapabilityResult? result, ResultTtlOptions ttl, DateTimeOffset now) =>
        result is not null && now - result.CheckedAt <= TimeSpan.FromMinutes(ttl.HomepageMinutes);
    public static bool StabilityFresh(ProxyStabilityResult? result, ResultTtlOptions ttl, DateTimeOffset now) =>
        result is not null && now - result.CheckedAt <= TimeSpan.FromMinutes(ttl.StabilityMinutes);
    public static bool BrowserFresh(BrowserVerificationResult? result, ResultTtlOptions ttl, DateTimeOffset now) =>
        result is not null && now - result.CheckedAt <= TimeSpan.FromMinutes(ttl.BrowserMinutes);
}

public static class CapabilityDecisionEngine
{
    public static ProxyCheckResult Evaluate(ProxyCheckResult result, GeoOptions geoOptions, TikTokVerificationOptions tikTokOptions,
        int maximumRecommendedLatencyMs = 2000)
    {
        var challenge = result.TikTokCapabilities.Any(x => x.Status == TikTokCapabilityStatus.Challenge)
            || result.BrowserPlayback.OriginalPostPlaybackResult?.Status == BrowserVerificationStatus.Challenge
            || result.BrowserPlayback.EmbedPlayerPlaybackResult?.Status == BrowserVerificationStatus.Challenge;
        var page = Passed(result, TikTokCapability.TikTokHomepage) || Passed(result, TikTokCapability.TikTokPostPage)
            || Passed(result, TikTokCapability.TikTokEmbedPlayer);
        var exitResolved = result.ExitIp?.Status == ExitIpStatus.Resolved;
        var technical = challenge ? TechnicalTikTokAccess.Challenge : page
            ? exitResolved && result.Geo is not null ? TechnicalTikTokAccess.Accessible : TechnicalTikTokAccess.AccessibleGeoUnknown
            : TechnicalTikTokAccess.None;
        var embedPlayback = result.BrowserPlayback.EmbedPlayerPlaybackResult?.Status == BrowserVerificationStatus.Passed;
        var originalPlayback = result.BrowserPlayback.OriginalPostPlaybackResult?.Status == BrowserVerificationStatus.Passed;
        var playback = originalPlayback ? PlaybackCapability.FullPlaybackVerified
            : embedPlayback ? PlaybackCapability.EmbedPlaybackVerified
            : Passed(result, TikTokCapability.TikTokEmbedPlayer) ? PlaybackCapability.EmbedPlayerAccessible
            : PlaybackCapability.None;
        var eligibility = GetEligibility(result, geoOptions, page, exitResolved, challenge, embedPlayback || originalPlayback, maximumRecommendedLatencyMs);
        var recommendation = Classify(result, technical, playback, eligibility);
        return result with { TechnicalAccess = technical, PlaybackCapability = playback,
            RecommendationEligibility = eligibility, RecommendationClass = recommendation };
    }

    private static RecommendationEligibility GetEligibility(ProxyCheckResult result, GeoOptions geoOptions, bool page,
        bool exitResolved, bool challenge, bool playback, int maximumLatency)
    {
        if (!page) return RecommendationEligibility.NoTechnicalAccess;
        if (!exitResolved) return RecommendationEligibility.ExitIpUnresolved;
        if (result.Geo?.Decision is GeoResolutionDecision.ConfirmedRussia or GeoResolutionDecision.LikelyRussia) return RecommendationEligibility.RussianExit;
        if (!GeoPolicy.IsRecommendationEligible(result.Geo, geoOptions)) return RecommendationEligibility.GeoInsufficient;
        if (challenge) return RecommendationEligibility.ChallengeDetected;
        if (result.Endpoint.HasCredentials) return RecommendationEligibility.CredentialsPresent;
        if (result.TikTokPageStability?.Status != ProxyStabilityStatus.Stable && result.Stability?.Status != ProxyStabilityStatus.Stable)
            return RecommendationEligibility.Unstable;
        if (!playback) return RecommendationEligibility.PlaybackUnverified;
        var latency = result.TikTokPageStability?.MedianLatencyMs ?? result.Stability?.MedianLatencyMs ?? 0;
        if (latency > maximumLatency) return RecommendationEligibility.LatencyTooHigh;
        return RecommendationEligibility.Eligible;
    }

    private static ProxyRecommendationClass Classify(ProxyCheckResult result, TechnicalTikTokAccess technical,
        PlaybackCapability playback, RecommendationEligibility eligibility)
    {
        if (eligibility is RecommendationEligibility.RussianExit or RecommendationEligibility.ChallengeDetected)
            return ProxyRecommendationClass.Rejected;
        if (eligibility == RecommendationEligibility.Eligible) return ProxyRecommendationClass.Recommended;
        if (playback == PlaybackCapability.FullPlaybackVerified) return ProxyRecommendationClass.FullPlaybackVerified;
        if (playback == PlaybackCapability.EmbedPlaybackVerified) return ProxyRecommendationClass.EmbedPlaybackVerified;
        if (playback == PlaybackCapability.EmbedPlayerAccessible) return ProxyRecommendationClass.EmbedPlayerAccessible;
        if (Passed(result, TikTokCapability.TikTokPostPage)) return ProxyRecommendationClass.PostPageAccessible;
        if ((result.TikTokPageStability ?? result.Stability)?.Status == ProxyStabilityStatus.Stable) return ProxyRecommendationClass.StablePageAccess;
        if (technical == TechnicalTikTokAccess.AccessibleGeoUnknown) return ProxyRecommendationClass.TikTokAccessibleGeoUnknown;
        if (Passed(result, TikTokCapability.TikTokHomepage)) return ProxyRecommendationClass.PageOnly;
        if (result.Probe?.Success == true) return ProxyRecommendationClass.ProtocolOnly;
        return ProxyRecommendationClass.Rejected;
    }

    private static bool Passed(ProxyCheckResult result, TikTokCapability capability) =>
        result.TikTokCapabilities.Any(x => x.Capability == capability && x.Status == TikTokCapabilityStatus.Passed);
}

public static class CapabilityMatrixBuilder
{
    public static CapabilityMatrix Build(IEnumerable<ProxyCheckResult> source)
    {
        var results = source.ToArray();
        bool Passed(ProxyCheckResult x, TikTokCapability c) => x.TikTokCapabilities.Any(y => y.Capability == c && y.Status == TikTokCapabilityStatus.Passed);
        bool MobileFailed(ProxyCheckResult x) => x.TikTokCapabilities.Any(y => y.Capability == TikTokCapability.TikTokMobilePage && y.Status != TikTokCapabilityStatus.Passed);
        var counts = new Dictionary<string, long>
        {
            ["HomepagePassed"] = results.Count(x => Passed(x, TikTokCapability.TikTokHomepage)),
            ["MobilePassed"] = results.Count(x => Passed(x, TikTokCapability.TikTokMobilePage)),
            ["HomepagePassedAndMobileFailed"] = results.Count(x => Passed(x, TikTokCapability.TikTokHomepage) && MobileFailed(x)),
            ["HomepagePassedAndExitUnresolved"] = results.Count(x => Passed(x, TikTokCapability.TikTokHomepage) && x.ExitIp?.Status != ExitIpStatus.Resolved),
            ["HomepagePassedAndStable"] = results.Count(x => Passed(x, TikTokCapability.TikTokHomepage) && (x.TikTokPageStability ?? x.Stability)?.Status == ProxyStabilityStatus.Stable),
            ["PostPagePassed"] = results.Count(x => Passed(x, TikTokCapability.TikTokPostPage)),
            ["OEmbedPassed"] = results.Count(x => Passed(x, TikTokCapability.TikTokOEmbed)),
            ["EmbedPlayerAccessible"] = results.Count(x => Passed(x, TikTokCapability.TikTokEmbedPlayer)),
            ["EmbedPlaybackVerified"] = results.Count(x => x.BrowserPlayback.EmbedPlayerPlaybackResult?.Status == BrowserVerificationStatus.Passed),
            ["OriginalPagePlaybackVerified"] = results.Count(x => x.BrowserPlayback.OriginalPostPlaybackResult?.Status == BrowserVerificationStatus.Passed)
        };
        var reasons = results.SelectMany(x => x.TikTokCapabilities)
            .Where(x => x.Status is TikTokCapabilityStatus.NotConfigured or TikTokCapabilityStatus.Skipped or TikTokCapabilityStatus.Unsupported)
            .GroupBy(x => x.Reason ?? "DependencyUnavailable").ToDictionary(x => x.Key, x => (long)x.Count());
        return new() { Counts = counts, NotRunReasons = reasons };
    }
}
