using Microsoft.Playwright;
using System.Collections.Concurrent;
using System.Diagnostics;
using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Infrastructure;

public sealed class PlaywrightBrowserProxyVerifier(BrowserVerificationOptions options, TikTokVerificationOptions tikTokOptions)
    : IBrowserProxyVerifier, IAdvancedBrowserProxyVerifier
{
    public async Task<BrowserVerificationResult> VerifyAsync(ProxyEndpoint endpoint, Uri videoUrl, CancellationToken cancellationToken)
        => await VerifyAsync(endpoint, videoUrl, BrowserVerificationMode.OriginalPostPage, cancellationToken);

    public async Task<BrowserVerificationResult> VerifyAsync(ProxyEndpoint endpoint, Uri videoUrl,
        BrowserVerificationMode mode, CancellationToken cancellationToken)
    {
        if (!TikTokVideoUrlParser.TryParse(videoUrl, tikTokOptions.AllowedVideoDomains, out _, out var playerUrl, out var parseReason))
            return Failed(videoUrl, BrowserVerificationStatus.NotConfigured, parseReason ?? "A valid public TikTok video URL is required") with { Mode = mode };
        var targetUrl = mode == BrowserVerificationMode.OfficialEmbedPlayer ? playerUrl! : videoUrl;
        if (endpoint.DetectedProtocol is ProxyProtocol.Socks4 or ProxyProtocol.Socks4a or ProxyProtocol.Http or ProxyProtocol.Unknown)
            return Skipped(videoUrl, $"Playwright does not support {endpoint.DetectedProtocol} for this HTTPS check") with { Mode = mode };
        if (endpoint.DetectedProtocol == ProxyProtocol.Socks5 && endpoint.HasCredentials)
            return Skipped(videoUrl, "Authenticated SOCKS5 is not supported by Chromium proxy configuration") with { Mode = mode };

        var watch = Stopwatch.StartNew();
        try
        {
            using var playwright = await Playwright.CreateAsync();
            var scheme = endpoint.DetectedProtocol == ProxyProtocol.Socks5 ? "socks5" : "http";
            var proxy = new Proxy
            {
                Server = $"{scheme}://{FormatHost(endpoint.Host)}:{endpoint.Port}",
                Username = endpoint.Username,
                Password = endpoint.Password
            };
            await using var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
            {
                Headless = true,
                Proxy = proxy
            });
            await using var context = await browser.NewContextAsync(new BrowserNewContextOptions
            {
                IgnoreHTTPSErrors = false,
                UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36"
            });
            var page = await context.NewPageAsync();
            await page.AddInitScriptAsync("""
window.__tphPlayerEvents = [];
window.addEventListener('message', event => {
  const data = event.data;
  if (data && data['x-tiktok-player']) window.__tphPlayerEvents.push({ type: String(data.type || ''), value: data.value });
});
""");
            var mediaResponses = 0;
            var mediaHosts = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
            var observations = new ConcurrentQueue<MediaRequestObservation>();
            var consoleErrors = new ConcurrentQueue<string>();
            var pageErrors = new ConcurrentQueue<string>();
            page.Console += (_, message) => { if (message.Type == "error") consoleErrors.Enqueue(Sanitize(message.Text)); };
            page.PageError += (_, error) => pageErrors.Enqueue(Sanitize(error));
            page.Response += (_, response) =>
            {
                if (!Uri.TryCreate(response.Url, UriKind.Absolute, out var responseUri)) return;
                response.Headers.TryGetValue("content-type", out var contentType);
                var observation = MediaRequestClassifier.Classify(responseUri, response.Status, contentType,
                    response.Request.ResourceType, response.Headers, options.AllowedCdnDomains);
                observations.Enqueue(observation);
                if (MediaRequestClassifier.IsSuccessfulMedia(observation))
                {
                    Interlocked.Increment(ref mediaResponses);
                    mediaHosts.TryAdd(responseUri.Host, 0);
                }
            };
            var navigation = await page.GotoAsync(targetUrl.AbsoluteUri, new PageGotoOptions
            {
                WaitUntil = WaitUntilState.DOMContentLoaded,
                Timeout = options.NavigationTimeoutSeconds * 1000
            });
            if (navigation is null) return Failed(videoUrl, BrowserVerificationStatus.Failed, "Navigation returned no response") with { Elapsed = watch.Elapsed };
            if (!TikTokResultClassifier.IsTikTokHost(new Uri(page.Url).Host))
                return await CompleteFailureAsync(page, endpoint, Failed(videoUrl, BrowserVerificationStatus.WrongDomain, "Navigation ended on an unexpected domain") with
                { NavigationStatus = navigation.Status, FinalUrl = SafeUrl(page.Url), ConsoleErrors = consoleErrors.ToArray(), PageErrors = pageErrors.ToArray(), Elapsed = watch.Elapsed });
            var text = await page.Locator("body").InnerTextAsync(new LocatorInnerTextOptions { Timeout = 5_000 });
            var expectedSurface = text.Contains("tiktok", StringComparison.OrdinalIgnoreCase)
                || await page.Locator("video, iframe, [class*='player'], [data-e2e*='player']").CountAsync() > 0;
            if (ContainsChallenge(text)) return await CompleteFailureAsync(page, endpoint,
                Failed(videoUrl, BrowserVerificationStatus.Challenge, "CAPTCHA or challenge detected") with
                { ChallengeDetected = true, NavigationStatus = navigation.Status, FinalUrl = SafeUrl(page.Url),
                    ConsoleErrors = consoleErrors.ToArray(), PageErrors = pageErrors.ToArray(), Elapsed = watch.Elapsed,
                    Mode = mode, ExpectedPlayerSurfaceFound = expectedSurface, MediaObservations = observations.ToArray() });
            var videos = page.Locator("video");
            var videoCount = await videos.CountAsync();
            var video = videos.First;
            if (videoCount == 0) return await CompleteFailureAsync(page, endpoint,
                Failed(videoUrl, BrowserVerificationStatus.MediaUnverified, "No video element found") with
                { VideoElementCount = 0, NavigationStatus = navigation.Status, FinalUrl = SafeUrl(page.Url),
                    ConsoleErrors = consoleErrors.ToArray(), PageErrors = pageErrors.ToArray(), Elapsed = watch.Elapsed,
                    Mode = mode, ExpectedPlayerSurfaceFound = expectedSurface, MediaObservations = observations.ToArray() });
            var before = await video.EvaluateAsync<VideoState>("v => ({ readyState: v.readyState, networkState: v.networkState, duration: Number.isFinite(v.duration) ? v.duration : null, currentTime: v.currentTime, hasError: !!v.error })");
            await video.EvaluateAsync("v => v.play().catch(() => undefined)");
            if (mode == BrowserVerificationMode.OfficialEmbedPlayer)
                await page.EvaluateAsync("window.postMessage({ type: 'play', 'x-tiktok-player': true }, '*')");
            await Task.Delay(TimeSpan.FromSeconds(options.PlaybackObservationSeconds), cancellationToken);
            var after = await video.EvaluateAsync<VideoState>("v => ({ readyState: v.readyState, networkState: v.networkState, duration: Number.isFinite(v.duration) ? v.duration : null, currentTime: v.currentTime, hasError: !!v.error })");
            var playerEvents = await page.EvaluateAsync<string[]>("(window.__tphPlayerEvents || []).map(x => String(x.type || ''))");
            var classified = BrowserVerificationClassifier.Classify(videoUrl, before, after, mediaResponses, options.MinimumPlaybackProgressSeconds) with
            { VideoElementCount = videoCount, InitialCurrentTimeSeconds = before.CurrentTime, FinalCurrentTimeSeconds = after.CurrentTime,
                NavigationStatus = navigation.Status, FinalUrl = SafeUrl(page.Url), MediaCdnHosts = mediaHosts.Keys.Order().ToArray(),
                ConsoleErrors = consoleErrors.ToArray(), PageErrors = pageErrors.ToArray(), Elapsed = watch.Elapsed,
                Mode = mode, ExpectedPlayerSurfaceFound = expectedSurface, MediaObservations = observations.ToArray(), PlayerEvents = playerEvents };
            if (!expectedSurface) classified = classified with { Status = BrowserVerificationStatus.MediaUnverified,
                Reason = "Expected TikTok player surface was not found" };
            return classified.Status == BrowserVerificationStatus.Passed ? classified : await CompleteFailureAsync(page, endpoint, classified);
        }
        catch (PlaywrightException ex)
        {
            var status = ex.Message.Contains("certificate", StringComparison.OrdinalIgnoreCase)
                || ex.Message.Contains("SSL", StringComparison.OrdinalIgnoreCase) ? BrowserVerificationStatus.TlsFailure
                : ex.Message.Contains("Executable doesn't exist", StringComparison.OrdinalIgnoreCase) ? BrowserVerificationStatus.Unavailable
                : BrowserVerificationStatus.Failed;
            return Failed(videoUrl, status, Sanitize(ex.Message)) with { Elapsed = watch.Elapsed, Mode = mode };
        }
        catch (TimeoutException) { return Failed(videoUrl, BrowserVerificationStatus.Timeout, "Navigation timeout") with { Elapsed = watch.Elapsed, Mode = mode }; }
    }

    private async Task<BrowserVerificationResult> CompleteFailureAsync(IPage page, ProxyEndpoint endpoint, BrowserVerificationResult result)
    {
        if (!options.CaptureScreenshotOnFailure) return result;
        try
        {
            Directory.CreateDirectory(options.ScreenshotDirectory);
            var safeKey = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(endpoint.NormalizedKey)))[..16].ToLowerInvariant();
            var path = Path.GetFullPath(Path.Combine(options.ScreenshotDirectory, $"{safeKey}.png"));
            await page.ScreenshotAsync(new() { Path = path, FullPage = false });
            return result with { ScreenshotPath = path };
        }
        catch (PlaywrightException) { return result; }
    }

    private static bool ContainsChallenge(string text) => text.Contains("captcha", StringComparison.OrdinalIgnoreCase)
        || text.Contains("verify you are human", StringComparison.OrdinalIgnoreCase)
        || text.Contains("access denied", StringComparison.OrdinalIgnoreCase);
    private static string FormatHost(string host) => host.Contains(':', StringComparison.Ordinal) ? $"[{host}]" : host;
    private static BrowserVerificationResult Skipped(Uri url, string reason) => Failed(url, BrowserVerificationStatus.Skipped, reason);
    private static BrowserVerificationResult Failed(Uri url, BrowserVerificationStatus status, string reason) =>
        new() { Url = url, Status = status, Reason = reason };
    private static string Sanitize(string message) => message.Length <= 500 ? message : message[..500];
    private static Uri? SafeUrl(string value) => Uri.TryCreate(value, UriKind.Absolute, out var uri)
        ? new Uri(uri.GetLeftPart(UriPartial.Path)) : null;

    public static bool IsAllowedMediaResponse(string url, string resourceType, IEnumerable<string> allowedDomains)
    {
        if (!resourceType.Equals("media", StringComparison.OrdinalIgnoreCase) || !Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
        return allowedDomains.Any(domain => uri.Host.Equals(domain, StringComparison.OrdinalIgnoreCase)
            || uri.Host.EndsWith('.' + domain, StringComparison.OrdinalIgnoreCase));
    }

    public sealed record VideoState(int ReadyState, int NetworkState, double? Duration, double CurrentTime, bool HasError);
}

public static class BrowserVerificationClassifier
{
    public static BrowserVerificationResult Classify(Uri url, PlaywrightBrowserProxyVerifier.VideoState before,
        PlaywrightBrowserProxyVerifier.VideoState after, int successfulMediaResponses, double minimumProgress)
    {
        var progress = Math.Max(0, after.CurrentTime - before.CurrentTime);
        var passed = !after.HasError && after.ReadyState >= 2 && progress >= minimumProgress && successfulMediaResponses > 0;
        return new BrowserVerificationResult
        {
            Url = url, Status = passed ? BrowserVerificationStatus.Passed : BrowserVerificationStatus.MediaUnverified,
            VideoElementFound = true, ReadyState = after.ReadyState, NetworkState = after.NetworkState,
            DurationSeconds = after.Duration, PlaybackProgressSeconds = progress, MediaError = after.HasError,
            SuccessfulMediaResponses = successfulMediaResponses,
            Reason = passed ? null : "Playback progress, media state, or CDN response criteria were not met"
        };
    }
}
