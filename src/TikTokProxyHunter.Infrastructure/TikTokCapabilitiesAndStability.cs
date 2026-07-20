using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Infrastructure;

public sealed partial class TikTokCapabilityVerifier(
    ITikTokChecker checker,
    ProxyHttpsClient proxyClient,
    HunterOptions hunterOptions,
    TikTokVerificationOptions options,
    ITikTokEmbedPlayerVerifier embedPlayerVerifier) : ITikTokCapabilityVerifier
{
    public async Task<IReadOnlyList<TikTokCapabilityResult>> VerifyFastAsync(ProxyEndpoint endpoint,
        IEnumerable<Uri> publicVideoUrls, CancellationToken cancellationToken)
    {
        var results = new List<TikTokCapabilityResult>();
        results.Add(await VerifyCapabilityAsync(endpoint, TikTokCapability.TikTokHomepage, null, cancellationToken));
        results.Add(await VerifyCapabilityAsync(endpoint, TikTokCapability.TikTokMobilePage, null, cancellationToken));
        var homepage = results[0];
        results.Insert(0, new TikTokCapabilityResult { Capability = TikTokCapability.TikTokDnsAndTunnel,
            Status = homepage.Status == TikTokCapabilityStatus.Passed ? TikTokCapabilityStatus.Passed : homepage.Status,
            Duration = homepage.Duration, Reason = homepage.Status == TikTokCapabilityStatus.Passed ? null : "Homepage TLS tunnel did not pass" });

        foreach (var videoUrl in publicVideoUrls.Distinct())
        {
            if (!IsValidPublicVideoUrl(videoUrl))
            {
                results.Add(new TikTokCapabilityResult { Capability = TikTokCapability.TikTokPublicVideoPage,
                    Status = TikTokCapabilityStatus.Skipped, Url = videoUrl, Reason = "URL is not a public TikTok video URL" });
                continue;
            }
            results.Add(await VerifyVideoPageAsync(endpoint, videoUrl, cancellationToken));
            results.Add(await VerifyOEmbedAsync(endpoint, videoUrl, cancellationToken));
            var embed = await embedPlayerVerifier.VerifyAsync(endpoint, videoUrl, cancellationToken);
            results.Add(new TikTokCapabilityResult { Capability = TikTokCapability.TikTokEmbedPlayer,
                Status = embed.Status, Url = embed.RequestedUrl, Duration = embed.Latency,
                HttpStatus = embed.HttpStatus, Reason = embed.FailureReason });
        }
        return results;
    }

    public async Task<TikTokCapabilityResult> VerifyCapabilityAsync(ProxyEndpoint endpoint, TikTokCapability capability,
        Uri? videoUrl, CancellationToken cancellationToken)
    {
        if (capability == TikTokCapability.ShortGenericHttps)
        {
            var watch = Stopwatch.StartNew();
            try
            {
                var response = await proxyClient.GetAsync(endpoint, new Uri("https://example.com/"), cancellationToken, 32_768);
                return new() { Capability = capability, Status = response.TlsValid && response.StatusCode is >= 200 and < 500
                    ? TikTokCapabilityStatus.Passed : TikTokCapabilityStatus.Failed, Url = new Uri("https://example.com/"),
                    Duration = watch.Elapsed, HttpStatus = response.StatusCode };
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            { return Failed(capability, new Uri("https://example.com/"), TikTokCapabilityStatus.Timeout, watch.Elapsed, "Timeout"); }
            catch (Exception ex) when (IsNetworkFailure(ex))
            { return Failed(capability, new Uri("https://example.com/"), TikTokCapabilityStatus.Unavailable, watch.Elapsed, ex.Message); }
        }
        if (capability is TikTokCapability.TikTokHomepage or TikTokCapability.TikTokMobilePage)
        {
            if (capability == TikTokCapability.TikTokMobilePage && !options.MobilePage.Enabled)
                return new() { Capability = capability, Status = TikTokCapabilityStatus.NotConfigured,
                    Reason = "TikTok.MobilePage.Enabled is false" };
            var urls = hunterOptions.TikTokUrls.Distinct(StringComparer.OrdinalIgnoreCase).Select(x => new Uri(x)).ToArray();
            var index = capability == TikTokCapability.TikTokHomepage ? 0 : 1;
            if (urls.Length <= index) return new() { Capability = capability, Status = TikTokCapabilityStatus.NotConfigured,
                Reason = $"No URL configured for {capability}" };
            var check = await checker.CheckAsync(endpoint, urls[index], cancellationToken);
            return new() { Capability = capability, Status = Map(check.Status), Url = check.Url,
                Duration = check.TotalTime, HttpStatus = check.HttpStatus, Reason = check.FailureReason };
        }
        if (videoUrl is null)
            return new() { Capability = capability, Status = TikTokCapabilityStatus.NotConfigured,
                Reason = "No enabled public TikTok test video is configured" };
        return capability switch
        {
            TikTokCapability.TikTokPublicVideoPage or TikTokCapability.TikTokPostPage => await VerifyVideoPageAsync(endpoint, videoUrl, cancellationToken),
            TikTokCapability.TikTokOEmbed => await VerifyOEmbedAsync(endpoint, videoUrl, cancellationToken),
            TikTokCapability.TikTokEmbedPlayer => ToCapability(await embedPlayerVerifier.VerifyAsync(endpoint, videoUrl, cancellationToken)),
            _ => new() { Capability = capability, Status = TikTokCapabilityStatus.Unsupported,
                Reason = $"Capability {capability} is not supported by the HTTP verifier" }
        };
    }

    private async Task<TikTokCapabilityResult> VerifyVideoPageAsync(ProxyEndpoint endpoint, Uri url, CancellationToken token)
    {
        var watch = Stopwatch.StartNew();
        try
        {
            var response = await proxyClient.GetAsync(endpoint, url, token, 2_000_000);
            return new TikTokCapabilityResult { Capability = TikTokCapability.TikTokPostPage,
                Status = TikTokContentClassifier.ClassifyVideoPage(response.StatusCode, response.Body, url), Url = url,
                Duration = watch.Elapsed, HttpStatus = response.StatusCode };
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        { return Failed(TikTokCapability.TikTokPostPage, url, TikTokCapabilityStatus.Timeout, watch.Elapsed, "Timeout"); }
        catch (Exception ex) when (ex is IOException or InvalidDataException or HttpRequestException or System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException)
        { return Failed(TikTokCapability.TikTokPostPage, url, TikTokCapabilityStatus.Unavailable, watch.Elapsed, ex.Message); }
    }

    private async Task<TikTokCapabilityResult> VerifyOEmbedAsync(ProxyEndpoint endpoint, Uri videoUrl, CancellationToken token)
    {
        var watch = Stopwatch.StartNew();
        try
        {
            var requestUrl = new Uri($"{options.OEmbedEndpoint}?url={Uri.EscapeDataString(videoUrl.AbsoluteUri)}");
            var response = await proxyClient.GetAsync(endpoint, requestUrl, token, 512_000);
            return new TikTokCapabilityResult { Capability = TikTokCapability.TikTokOEmbed,
                Status = TikTokContentClassifier.ClassifyOEmbed(response.StatusCode, response.Body, videoUrl), Url = videoUrl,
                Duration = watch.Elapsed, HttpStatus = response.StatusCode };
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        { return Failed(TikTokCapability.TikTokOEmbed, videoUrl, TikTokCapabilityStatus.Timeout, watch.Elapsed, "Timeout"); }
        catch (Exception ex) when (ex is IOException or InvalidDataException or HttpRequestException or System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException)
        { return Failed(TikTokCapability.TikTokOEmbed, videoUrl, TikTokCapabilityStatus.Unavailable, watch.Elapsed, ex.Message); }
    }

    public static bool IsValidPublicVideoUrl(Uri url) => url.Scheme == Uri.UriSchemeHttps
        && TikTokResultClassifier.IsTikTokHost(url.Host) && VideoPathRegex().IsMatch(url.AbsolutePath);

    private static TikTokCapabilityStatus Map(TikTokStatus status) => status switch
    {
        TikTokStatus.Accessible => TikTokCapabilityStatus.Passed,
        TikTokStatus.CaptchaOrChallenge => TikTokCapabilityStatus.Challenge,
        TikTokStatus.Forbidden or TikTokStatus.AccessibleButBlocked => TikTokCapabilityStatus.Blocked,
        TikTokStatus.RateLimited => TikTokCapabilityStatus.RateLimited,
        TikTokStatus.InvalidContent => TikTokCapabilityStatus.InvalidContent,
        TikTokStatus.Timeout => TikTokCapabilityStatus.Timeout,
        TikTokStatus.ConnectionFailure => TikTokCapabilityStatus.Unavailable,
        _ => TikTokCapabilityStatus.Failed
    };

    private static TikTokCapabilityResult Failed(TikTokCapability capability, Uri url, TikTokCapabilityStatus status, TimeSpan duration, string reason) =>
        new() { Capability = capability, Url = url, Status = status, Duration = duration, Reason = reason };

    private static TikTokCapabilityResult ToCapability(TikTokEmbedPlayerResult result) => new()
    { Capability = TikTokCapability.TikTokEmbedPlayer, Status = result.Status, Url = result.RequestedUrl,
      Duration = result.Latency, HttpStatus = result.HttpStatus, Reason = result.FailureReason };
    private static bool IsNetworkFailure(Exception ex) => ex is IOException or InvalidDataException or HttpRequestException
        or System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException or NotSupportedException;

    [GeneratedRegex(@"/(?:@[^/]+/video/|v/)(?<id>\d{5,})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex VideoPathRegex();
}

public static partial class TikTokContentClassifier
{
    public static TikTokCapabilityStatus ClassifyVideoPage(int status, string body, Uri requestedUrl)
    {
        if (status == 429) return TikTokCapabilityStatus.RateLimited;
        if (status is 401 or 403) return TikTokCapabilityStatus.Blocked;
        if (ContainsChallenge(body)) return TikTokCapabilityStatus.Challenge;
        if (status is < 200 or >= 400) return TikTokCapabilityStatus.Failed;
        var match = VideoIdRegex().Match(requestedUrl.AbsolutePath);
        if (!match.Success || !body.Contains(match.Groups["id"].Value, StringComparison.Ordinal)) return TikTokCapabilityStatus.InvalidContent;
        var hasMetadata = body.Contains("og:video", StringComparison.OrdinalIgnoreCase)
            || body.Contains("twitter:player", StringComparison.OrdinalIgnoreCase)
            || body.Contains("__UNIVERSAL_DATA_FOR_REHYDRATION__", StringComparison.Ordinal);
        return hasMetadata ? TikTokCapabilityStatus.Passed : TikTokCapabilityStatus.MediaUnverified;
    }

    public static TikTokCapabilityStatus ClassifyOEmbed(int status, string body, Uri requestedUrl)
    {
        if (status == 429) return TikTokCapabilityStatus.RateLimited;
        if (status is 401 or 403) return TikTokCapabilityStatus.Blocked;
        if (status is < 200 or >= 300) return TikTokCapabilityStatus.Failed;
        try
        {
            using var json = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 32 });
            var root = json.RootElement;
            if (!root.TryGetProperty("html", out var html) || !root.TryGetProperty("title", out _)) return TikTokCapabilityStatus.InvalidContent;
            var match = VideoIdRegex().Match(requestedUrl.AbsolutePath);
            return match.Success && html.ToString().Contains(match.Groups["id"].Value, StringComparison.Ordinal)
                ? TikTokCapabilityStatus.Passed : TikTokCapabilityStatus.InvalidContent;
        }
        catch (JsonException) { return TikTokCapabilityStatus.InvalidContent; }
    }

    private static bool ContainsChallenge(string body) => body.Contains("captcha", StringComparison.OrdinalIgnoreCase)
        || body.Contains("verify you are human", StringComparison.OrdinalIgnoreCase)
        || body.Contains("cf-chl-", StringComparison.OrdinalIgnoreCase);
    [GeneratedRegex(@"/(?:@[^/]+/video/|v/)(?<id>\d{5,})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex VideoIdRegex();
}

public sealed class ProxyStabilityChecker(
    ITikTokCapabilityVerifier capabilityVerifier,
    StabilityOptions options) : IProxyStabilityChecker
{
    public async Task<ProxyStabilityResult> CheckAsync(ProxyEndpoint endpoint, CancellationToken cancellationToken)
        => await CheckAsync(endpoint, TikTokCapability.TikTokHomepage, null, cancellationToken);

    public async Task<ProxyStabilityResult> CheckAsync(ProxyEndpoint endpoint, TikTokCapability capability,
        Uri? videoUrl, CancellationToken cancellationToken)
    {
        var attempts = new List<ProxyCheckAttempt>();
        for (var attempt = 1; attempt <= options.Attempts; attempt++)
        {
            var watch = Stopwatch.StartNew();
            try
            {
                var result = await capabilityVerifier.VerifyCapabilityAsync(endpoint, capability, videoUrl, cancellationToken);
                var success = result.Status == TikTokCapabilityStatus.Passed;
                attempts.Add(new ProxyCheckAttempt { Attempt = attempt, Success = success, Latency = watch.Elapsed,
                    Status = result.Status, Error = success ? null : result.Reason ?? result.Status.ToString() });
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or HttpRequestException or OperationCanceledException)
            {
                if (cancellationToken.IsCancellationRequested) throw;
                attempts.Add(new ProxyCheckAttempt { Attempt = attempt, Success = false, Latency = watch.Elapsed,
                    Status = TikTokCapabilityStatus.Unavailable, Error = ex.Message });
            }
            if (attempt < options.Attempts && options.DelaySeconds > 0)
                await Task.Delay(TimeSpan.FromSeconds(options.DelaySeconds), cancellationToken);
        }
        return StabilityCalculator.Calculate(attempts, options) with { Capability = capability };
    }
}

public static class StabilityCalculator
{
    public static ProxyStabilityResult Calculate(IReadOnlyList<ProxyCheckAttempt> attempts, StabilityOptions options)
    {
        if (attempts.Count == 0) return new ProxyStabilityResult { Status = ProxyStabilityStatus.NotEnoughData };
        var ratio = attempts.Count(x => x.Success) / (double)attempts.Count;
        var latencies = attempts.Select(x => x.Latency.TotalMilliseconds).Order().ToArray();
        var median = Median(latencies);
        var jitter = latencies.Length < 2 ? 0 : Math.Sqrt(latencies.Sum(x => Math.Pow(x - latencies.Average(), 2)) / latencies.Length);
        var exits = attempts.Where(x => x.Success && x.ExitIp is not null).Select(x => x.ExitIp!).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var status = attempts.Count < 2 ? ProxyStabilityStatus.NotEnoughData
            : ratio == 0 ? ProxyStabilityStatus.Dead
            : ratio >= options.MinimumSuccessRatio && jitter <= options.MaximumAllowedJitterMs ? ProxyStabilityStatus.Stable
            : ratio < options.MinimumSuccessRatio ? ProxyStabilityStatus.Intermittent : ProxyStabilityStatus.Unstable;
        return new ProxyStabilityResult { Status = status, Attempts = attempts, SuccessRatio = ratio,
            MedianLatencyMs = median, JitterMs = jitter, StableExitIp = exits.Length == 1,
            FailureSequence = string.Join(" -> ", attempts.Select(x => x.Success ? "OK" : x.Status.ToString())) };
    }

    private static double Median(double[] values) => values.Length == 0 ? 0
        : (values[(values.Length - 1) / 2] + values[values.Length / 2]) / 2;
}

public static class RecommendationClassifier
{
    public static ProxyRecommendationClass Classify(ProxyCheckResult result, GeoOptions geoOptions)
    {
        if (result.Geo?.Decision is GeoResolutionDecision.ConfirmedRussia or GeoResolutionDecision.LikelyRussia
            || result.TikTokChecks.Any(x => x.Status is TikTokStatus.TlsFailure or TikTokStatus.InvalidContent)
            || result.TikTokCapabilities.Any(x => x.Status == TikTokCapabilityStatus.Challenge)) return ProxyRecommendationClass.Rejected;
        var browser = result.BrowserVerification?.Status == BrowserVerificationStatus.Passed;
        var video = result.TikTokCapabilities.Any(x => x.Capability == TikTokCapability.TikTokPublicVideoPage && x.Status == TikTokCapabilityStatus.Passed);
        var stable = result.Stability?.Status == ProxyStabilityStatus.Stable;
        var validExit = result.ExitIp?.Status == ExitIpStatus.Resolved;
        var tlsTunnel = result.TikTokCapabilities.Any(x => x.Capability == TikTokCapability.TikTokDnsAndTunnel && x.Status == TikTokCapabilityStatus.Passed);
        var acceptableLatency = result.Stability is { MedianLatencyMs: > 0 and <= 800 };
        if (GeoPolicy.IsRecommendationEligible(result.Geo, geoOptions) && validExit && tlsTunnel && video && stable && acceptableLatency && result.Score.Value >= 60)
            return ProxyRecommendationClass.Recommended;
        if (browser) return ProxyRecommendationClass.PlaybackVerified;
        if (video) return ProxyRecommendationClass.VideoPageAccessible;
        if (result.TikTokCapabilities.Any(x => x.Capability == TikTokCapability.TikTokHomepage && x.Status == TikTokCapabilityStatus.Passed))
            return ProxyRecommendationClass.PageOnly;
        return ProxyRecommendationClass.Rejected;
    }
}

public static class TikTokCapabilityAggregator
{
    public static bool Passed(IEnumerable<TikTokCapabilityResult> results, TikTokCapability capability) =>
        results.Any(x => x.Capability == capability && x.Status == TikTokCapabilityStatus.Passed);
    public static bool HasChallenge(IEnumerable<TikTokCapabilityResult> results) =>
        results.Any(x => x.Status == TikTokCapabilityStatus.Challenge);
}
