using System.Net;
using Microsoft.AspNetCore.Http;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Echo;
using TikTokProxyHunter.Infrastructure;

namespace TikTokProxyHunter.Tests;

public sealed class Stage22Tests
{
    [Theory]
    [InlineData(TikTokCapabilityStatus.Failed)]
    [InlineData(TikTokCapabilityStatus.Unavailable)]
    public void Optional_mobile_does_not_block_stability_or_recommendation(TikTokCapabilityStatus mobileStatus)
    {
        var evaluated = CapabilityDecisionEngine.Evaluate(ReadyForRecommendation(mobileStatus), new GeoOptions(), new TikTokVerificationOptions());
        Assert.Equal(TechnicalTikTokAccess.Accessible, evaluated.TechnicalAccess);
        Assert.Equal(RecommendationEligibility.Eligible, evaluated.RecommendationEligibility);
        Assert.Equal(ProxyRecommendationClass.Recommended, evaluated.RecommendationClass);
    }

    [Fact]
    public void Homepage_success_is_stability_eligible_without_mobile()
    {
        var value = Base() with { TikTokCapabilities = [Passed(TikTokCapability.TikTokHomepage),
            Result(TikTokCapability.TikTokMobilePage, TikTokCapabilityStatus.Unavailable)],
            TikTokPageStability = Stable() };
        var evaluated = CapabilityDecisionEngine.Evaluate(value, new GeoOptions(), new TikTokVerificationOptions());
        Assert.Equal(ProxyRecommendationClass.StablePageAccess, evaluated.RecommendationClass);
    }

    [Fact]
    public void Exit_failure_does_not_block_technical_access_but_blocks_recommendation()
    {
        var value = ReadyForRecommendation(TikTokCapabilityStatus.Unavailable) with
        { ExitIp = new() { Status = ExitIpStatus.Unavailable }, Geo = null };
        var evaluated = CapabilityDecisionEngine.Evaluate(value, new GeoOptions(), new TikTokVerificationOptions());
        Assert.Equal(TechnicalTikTokAccess.AccessibleGeoUnknown, evaluated.TechnicalAccess);
        Assert.Equal(RecommendationEligibility.ExitIpUnresolved, evaluated.RecommendationEligibility);
        Assert.NotEqual(ProxyRecommendationClass.Recommended, evaluated.RecommendationClass);
    }

    [Fact]
    public void Confirmed_russian_exit_is_finally_rejected_even_when_page_is_stable()
    {
        var value = ReadyForRecommendation(TikTokCapabilityStatus.Unavailable) with
        { Geo = new() { IpAddress = "203.0.113.10", CountryCode = "RU",
            Decision = GeoResolutionDecision.ConfirmedRussia, ConfidenceLevel = GeoConfidenceLevel.High } };
        var evaluated = CapabilityDecisionEngine.Evaluate(value, new GeoOptions(), new TikTokVerificationOptions());
        Assert.Equal(RecommendationEligibility.RussianExit, evaluated.RecommendationEligibility);
        Assert.Equal(ProxyRecommendationClass.Rejected, evaluated.RecommendationClass);
    }

    [Fact]
    public void Provider_rate_limit_trips_circuit_and_planner_falls_back()
    {
        var breaker = new ExitIpProviderCircuitBreaker();
        var options = new ExitIpOptions { RateLimitCooldownSeconds = 60 };
        breaker.Record("limited", ExitIpStatus.ProviderBlocked, 429, "rate limited", options);
        var selected = ExitIpProviderPlanner.Select([
            Provider("limited", "family-a", 100), Provider("fallback", "family-b", 90)], breaker, 2);
        Assert.DoesNotContain(selected, x => x.Name == "limited");
        Assert.Contains(selected, x => x.Name == "fallback");
        Assert.Equal(ExitIpProviderHealthStatus.RateLimited, breaker.Snapshot(["limited"])[0].Status);
    }

    [Fact]
    public void Proxy_socket_failures_do_not_globally_disable_provider()
    {
        var breaker = new ExitIpProviderCircuitBreaker();
        var options = new ExitIpOptions { CircuitBreakerFailureThreshold = 2 };
        breaker.Record("provider", ExitIpStatus.Timeout, null, "proxy timeout", options);
        breaker.Record("provider", ExitIpStatus.Timeout, null, "proxy timeout", options);
        Assert.True(breaker.CanUse("provider", DateTimeOffset.UtcNow));
        Assert.Equal(ExitIpProviderHealthStatus.Degraded, breaker.Snapshot(["provider"])[0].Status);
    }

    [Theory]
    [InlineData("203.0.113.10")]
    [InlineData("{\"ip\":\"203.0.113.10\"}")]
    public void Custom_echo_plain_and_json_responses_are_parsed(string body)
    {
        Assert.True(ExitIpResolver.TryParseIp(body, null, out var ip));
        Assert.Equal("203.0.113.10", ip);
    }

    [Fact]
    public void Echo_service_uses_socket_peer_not_forwarded_header()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.7");
        context.Request.Headers["X-Forwarded-For"] = "203.0.113.99";
        Assert.Equal("198.51.100.7", EchoAddressResolver.Resolve(context));
    }

    [Fact]
    public void TikTok_post_id_and_official_player_url_are_deterministic()
    {
        var post = new Uri("https://www.tiktok.com/@sample/video/7481234567890123456");
        Assert.True(TikTokVideoUrlParser.TryParse(post, ["tiktok.com"], out var id, out var player, out var reason), reason);
        Assert.Equal("7481234567890123456", id);
        Assert.Equal("https://www.tiktok.com/player/v1/7481234567890123456", player!.AbsoluteUri);
    }

    [Theory]
    [InlineData("http://www.tiktok.com/@x/video/7481234567890123456")]
    [InlineData("https://evil.example/@x/video/7481234567890123456")]
    [InlineData("https://www.tiktok.com/@x/video/not-a-number")]
    [InlineData("https://www.tiktok.com/@x/video/7481234567890123456?token=secret")]
    public void Invalid_or_sensitive_video_url_is_rejected(string value)
    {
        Assert.False(TikTokVideoUrlParser.TryParse(new Uri(value), ["tiktok.com"], out _, out _, out _));
    }

    [Fact]
    public void Embed_player_html_requires_player_marker_and_matching_post_id()
    {
        var url = new Uri("https://www.tiktok.com/player/v1/7481234567890123456");
        var passed = TikTokEmbedPlayerClassifier.Classify("7481234567890123456", url, 200,
            "<html><div id='x-tiktok-player'>7481234567890123456</div></html>", new Dictionary<string, string>(), TimeSpan.Zero, ["x-tiktok-player"]);
        var wrong = TikTokEmbedPlayerClassifier.Classify("7481234567890123456", url, 200,
            "<html>generic player</html>", new Dictionary<string, string>(), TimeSpan.Zero, ["x-tiktok-player"]);
        Assert.Equal(TikTokCapabilityStatus.Passed, passed.Status);
        Assert.Equal(TikTokCapabilityStatus.InvalidContent, wrong.Status);
    }

    [Fact]
    public void Independent_capability_matrix_preserves_mobile_failure_and_unresolved_exit()
    {
        var result = Base() with { TikTokCapabilities = [Passed(TikTokCapability.TikTokHomepage),
            Result(TikTokCapability.TikTokMobilePage, TikTokCapabilityStatus.Unavailable)],
            TikTokPageStability = Stable() };
        var matrix = CapabilityMatrixBuilder.Build([result]);
        Assert.Equal(1, matrix.Counts["HomepagePassedAndMobileFailed"]);
        Assert.Equal(1, matrix.Counts["HomepagePassedAndExitUnresolved"]);
        Assert.Equal(1, matrix.Counts["HomepagePassedAndStable"]);
    }

    [Theory]
    [InlineData(4, 1, BrowserVerificationStatus.Passed)]
    [InlineData(4, 0, BrowserVerificationStatus.MediaUnverified)]
    [InlineData(0, 1, BrowserVerificationStatus.MediaUnverified)]
    public void Playback_requires_both_progress_and_media_response(double progress, int mediaResponses, BrowserVerificationStatus expected)
    {
        var before = new PlaywrightBrowserProxyVerifier.VideoState(3, 1, 10, 0, false);
        var after = new PlaywrightBrowserProxyVerifier.VideoState(3, 1, 10, progress, false);
        var result = BrowserVerificationClassifier.Classify(new Uri("https://www.tiktok.com/player/v1/7481234567890123456"),
            before, after, mediaResponses, 3);
        Assert.Equal(expected, result.Status);
    }

    [Fact]
    public void Signed_media_query_is_never_stored()
    {
        var uri = new Uri("https://v16.tiktokcdn.com/video/verylongsignedtoken1234567890?token=secret&expires=1");
        var item = MediaRequestClassifier.Classify(uri, 206, "video/mp4", "media",
            new Dictionary<string, string> { ["content-range"] = "bytes 0-99/100" }, ["tiktokcdn.com"]);
        Assert.Equal(MediaRequestCategory.TikTokMedia, item.Category);
        Assert.DoesNotContain("secret", item.PathPattern);
        Assert.DoesNotContain('?', item.PathPattern);
        Assert.Contains("{id}", item.PathPattern);
    }

    [Fact]
    public void Fresh_results_are_reused_and_expired_results_are_not()
    {
        var now = DateTimeOffset.UtcNow; var ttl = new ResultTtlOptions { ProtocolMinutes = 30, HomepageMinutes = 15 };
        Assert.True(ResultFreshness.ProtocolFresh(new ProxyProbeResult { Endpoint = Endpoint(), Success = true, CheckedAt = now.AddMinutes(-29) }, ttl, now));
        Assert.False(ResultFreshness.ProtocolFresh(new ProxyProbeResult { Endpoint = Endpoint(), Success = true, CheckedAt = now.AddMinutes(-31) }, ttl, now));
        Assert.True(ResultFreshness.CapabilityFresh(Passed(TikTokCapability.TikTokHomepage) with { CheckedAt = now.AddMinutes(-14) }, ttl, now));
        Assert.False(ResultFreshness.CapabilityFresh(Passed(TikTokCapability.TikTokHomepage) with { CheckedAt = now.AddMinutes(-16) }, ttl, now));
    }

    [Fact]
    public void Not_configured_capability_always_has_reason()
    {
        var result = Result(TikTokCapability.TikTokEmbedPlayer, TikTokCapabilityStatus.NotConfigured,
            $"{CapabilityNotRunReason.NotConfigured}: no test video");
        var matrix = CapabilityMatrixBuilder.Build([Base() with { TikTokCapabilities = [result] }]);
        Assert.NotNull(result.Reason);
        Assert.Contains("NotConfigured", matrix.NotRunReasons.Keys.Single());
    }

    [Fact]
    public async Task User_exports_separate_classes_and_strip_credentials_and_tokens()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"tph-22-{Guid.NewGuid():N}");
        try
        {
            var recommended = CapabilityDecisionEngine.Evaluate(ReadyForRecommendation(TikTokCapabilityStatus.Unavailable),
                new GeoOptions(), new TikTokVerificationOptions());
            var unresolved = CapabilityDecisionEngine.Evaluate(recommended with { ExitIp = null, Geo = null },
                new GeoOptions(), new TikTokVerificationOptions());
            var secret = recommended with { Endpoint = Endpoint("secret.example") with { Username = "alice-private", Password = "super-secret-credential" } };
            await new Stage2ResultExporter().ExportUserListsAsync(directory, [recommended, unresolved, secret], new GeoOptions(), true, CancellationToken.None);
            var all = string.Join('\n', Directory.GetFiles(directory).Select(File.ReadAllText));
            Assert.Contains(recommended.Endpoint.Host, await File.ReadAllTextAsync(Path.Combine(directory, "recommended.txt")));
            Assert.Contains(unresolved.Endpoint.Host, await File.ReadAllTextAsync(Path.Combine(directory, "geo-unresolved-but-working.txt")));
            Assert.DoesNotContain("alice-private", all); Assert.DoesNotContain("super-secret-credential", all); Assert.DoesNotContain("token=", all);
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
    }

    private static ProxyCheckResult ReadyForRecommendation(TikTokCapabilityStatus mobile) => Base() with
    {
        ExitIp = new() { Status = ExitIpStatus.Resolved, ExitIp = "203.0.113.10" },
        Geo = new() { IpAddress = "203.0.113.10", CountryCode = "KZ", Decision = GeoResolutionDecision.ConfirmedNonRussia,
            ConfidenceLevel = GeoConfidenceLevel.High },
        TikTokCapabilities = [Passed(TikTokCapability.TikTokHomepage), Result(TikTokCapability.TikTokMobilePage, mobile)],
        TikTokPageStability = Stable(), Stability = Stable(),
        BrowserPlayback = new() { EmbedPlayerPlaybackResult = new() { Status = BrowserVerificationStatus.Passed,
            Mode = BrowserVerificationMode.OfficialEmbedPlayer, PlaybackProgressSeconds = 4, SuccessfulMediaResponses = 1 } }
    };

    private static ProxyCheckResult Base() => new()
    {
        Endpoint = Endpoint(),
        Probe = new ProxyProbeResult { Endpoint = Endpoint(), Success = true, Protocol = ProxyProtocol.Socks5 }
    };

    private static ProxyEndpoint Endpoint(string host = "proxy.example") => new()
    { Host = host, Port = 1080, Source = "test", Sources = ["test"], SourceFamilies = ["independent"],
      NormalizedKey = $"socks5|{host}:1080", DetectedProtocol = ProxyProtocol.Socks5 };
    private static TikTokCapabilityResult Passed(TikTokCapability capability) => Result(capability, TikTokCapabilityStatus.Passed);
    private static TikTokCapabilityResult Result(TikTokCapability capability, TikTokCapabilityStatus status, string? reason = null) =>
        new() { Capability = capability, Status = status, Reason = reason };
    private static ProxyStabilityResult Stable() => new() { Status = ProxyStabilityStatus.Stable, MedianLatencyMs = 400,
        SuccessRatio = 1, Attempts = [new() { Attempt = 1, Success = true, Status = TikTokCapabilityStatus.Passed },
            new() { Attempt = 2, Success = true, Status = TikTokCapabilityStatus.Passed },
            new() { Attempt = 3, Success = true, Status = TikTokCapabilityStatus.Passed }] };
    private static ExitIpProvider Provider(string name, string family, int priority) => new()
    { Name = name, Family = family, Priority = priority, Url = $"https://{name}.example/ip" };
}
