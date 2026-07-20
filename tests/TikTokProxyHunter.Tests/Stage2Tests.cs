using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Infrastructure;

namespace TikTokProxyHunter.Tests;

public sealed class Stage2Tests
{
    [Theory]
    [InlineData(429, null, ProxySourceHealthStatus.RateLimited)]
    [InlineData(401, null, ProxySourceHealthStatus.AuthenticationRequired)]
    [InlineData(null, "CAPTCHA challenge", ProxySourceHealthStatus.Captcha)]
    [InlineData(null, "Oversized payload", ProxySourceHealthStatus.Oversized)]
    [InlineData(null, "Suspicious binary content", ProxySourceHealthStatus.SuspiciousContent)]
    public void Source_health_classifies_failures(int? status, string? error, ProxySourceHealthStatus expected)
    {
        var definition = SourceDefinition();
        var result = new ProxySourceResult { SourceName = definition.Name, HttpStatus = status, Error = error };
        var health = new SourceHealthEvaluator().Evaluate(definition, result, 0, 0, 2);
        Assert.Equal(expected, health.Status);
    }

    [Fact]
    public void Fingerprint_is_deterministic_and_detects_exact_mirrors()
    {
        var service = new SourceContentFingerprintService();
        var hash = service.ComputeSha256("8.8.8.8:80\n"u8);
        Assert.Equal(hash, service.ComputeSha256("8.8.8.8:80\n"u8));
        var mirrors = service.FindExactMirrors([
            new ProxySourceHealth { SourceName = "a", ContentSha256 = hash },
            new ProxySourceHealth { SourceName = "b", ContentSha256 = hash }
        ]);
        Assert.Equal("a", mirrors["b"]);
    }

    [Fact]
    public async Task Source_loader_uses_etag_and_cached_payload_for_304()
    {
        var requests = new List<HttpRequestMessage>(); var call = 0;
        var handler = new DelegateHandler(request =>
        {
            requests.Add(CloneHeaders(request));
            if (call++ == 0)
            {
                var ok = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("8.8.8.8:80") };
                ok.Headers.ETag = new EntityTagHeaderValue("\"v1\""); return ok;
            }
            return new HttpResponseMessage(HttpStatusCode.NotModified);
        });
        var cacheDirectory = Path.Combine(Path.GetTempPath(), "tiktok-proxy-hunter-cache-" + Guid.NewGuid().ToString("N"));
        try
        {
            var fingerprints = new SourceContentFingerprintService();
            var source = new TextProxySource(new TestHttpClientFactory(handler), new HunterOptions(),
                new SourcePayloadCache(fingerprints, cacheDirectory), fingerprints, NullLogger<TextProxySource>.Instance);
            var definition = SourceDefinition() with { ExpectedContentType = "text/plain" };
            var first = await source.LoadAsync(definition, CancellationToken.None);
            var second = await source.LoadAsync(definition, CancellationToken.None);
            Assert.True(first.Success); Assert.True(second.Success); Assert.True(second.FromCache);
            Assert.Equal(first.Content, second.Content);
            Assert.Contains(requests[1].Headers.IfNoneMatch, x => x.Tag == "\"v1\"");
        }
        finally { if (Directory.Exists(cacheDirectory)) Directory.Delete(cacheDirectory, true); }
    }

    [Fact]
    public async Task Oversized_source_payload_is_rejected_before_reading()
    {
        var handler = new DelegateHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[128]) });
        var fingerprint = new SourceContentFingerprintService();
        var source = new TextProxySource(new TestHttpClientFactory(handler), new HunterOptions { MaximumSourcePayloadBytes = 64 },
            new SourcePayloadCache(fingerprint, Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"))), fingerprint,
            NullLogger<TextProxySource>.Instance);
        var result = await source.LoadAsync(SourceDefinition() with { MaximumDownloadBytes = 64 }, CancellationToken.None);
        Assert.False(result.Success); Assert.Contains("Oversized", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GitHub_rate_limit_and_token_redaction_are_safe()
    {
        Assert.True(GitHubApiDiagnostics.IsRateLimited(HttpStatusCode.Forbidden, 0));
        Assert.True(GitHubApiDiagnostics.IsRateLimited(HttpStatusCode.TooManyRequests, 10));
        Assert.Equal("request Bearer *** failed", GitHubTokenRedactor.Redact("request Bearer ghp_secret failed", "ghp_secret"));
    }

    [Theory]
    [InlineData(5, 10, "MIT", false, SourceDiscoveryStatus.Rejected)]
    [InlineData(10, 10, "Unknown", false, SourceDiscoveryStatus.Candidate)]
    [InlineData(10, 10, "MIT", false, SourceDiscoveryStatus.AcceptedForReview)]
    [InlineData(10, 10, "MIT", true, SourceDiscoveryStatus.Duplicate)]
    public void Discovery_policy_classifies_candidates(int valid, int minimum, string license, bool duplicate, SourceDiscoveryStatus expected) =>
        Assert.Equal(expected, SourceDiscoveryPolicy.Classify(valid, minimum, license, duplicate));

    [Fact]
    public async Task Streaming_pipeline_handles_large_text_with_bounded_channel()
    {
        var content = new StringBuilder();
        const int count = 20_000;
        for (var i = 0; i < count; i++) content.AppendLine($"11.{i / 65536}.{(i / 256) % 256}.{i % 256}:{1000 + i}");
        var options = new HunterOptions { ChannelCapacity = 17, MaximumCandidates = 0, DeduplicationMemoryLimit = 25_000 };
        var processor = new StreamingCandidateProcessor([new TextProxyParser()],
            new ProxyNormalizer(new NormalizationOptions()), options);
        var definition = SourceDefinition();
        var result = await processor.ProcessAsync([(definition, new ProxySourceResult
        { SourceName = definition.Name, Success = true, Content = content.ToString() })], CancellationToken.None);
        Assert.Equal(count, result.Candidates); Assert.Equal(count, result.Endpoints.Count); Assert.Equal(0, result.DroppedByMemoryLimit);
    }

    [Fact]
    public void Exit_ip_consensus_requires_multiple_matching_providers()
    {
        var service = new ExitIpConsensusService();
        var result = service.Resolve([
            new("a", ExitIpStatus.Resolved, "8.8.8.8", TimeSpan.Zero),
            new("b", ExitIpStatus.Resolved, "8.8.8.8", TimeSpan.Zero),
            new("c", ExitIpStatus.Resolved, "1.1.1.1", TimeSpan.Zero)
        ], "9.9.9.9", 2);
        Assert.Equal(ExitIpStatus.Resolved, result.Status); Assert.Equal("8.8.8.8", result.ExitIp);
    }

    [Fact]
    public void Exit_ip_equal_to_direct_is_marked_ineffective()
    {
        var result = new ExitIpConsensusService().Resolve([
            new("a", ExitIpStatus.Resolved, "8.8.8.8", TimeSpan.Zero),
            new("b", ExitIpStatus.Resolved, "8.8.8.8", TimeSpan.Zero)
        ], "8.8.8.8", 2);
        Assert.Equal(ExitIpStatus.SameAsDirectIp, result.Status); Assert.True(result.IsTransparentOrIneffective);
    }

    [Fact]
    public void Geo_consensus_and_ru_policy_use_exit_country()
    {
        var geo = new GeoConsensusService().Resolve("8.8.8.8", [
            Geo("8.8.8.8", "RU", "a"), Geo("8.8.8.8", "RU", "b"), Geo("8.8.8.8", "KZ", "c")
        ], 2);
        Assert.Equal(ProxyGeoStatus.Resolved, geo.Status); Assert.Equal("RU", geo.CountryCode);
        Assert.True(GeoPolicy.IsRejected(geo, new GeoOptions()));
    }

    [Fact]
    public void Unknown_country_obeys_allow_unknown_setting()
    {
        var unknown = new ProxyGeoInfo { IpAddress = "8.8.8.8", Status = ProxyGeoStatus.GeoUncertain };
        Assert.True(GeoPolicy.IsRejected(unknown, new GeoOptions { AllowUnknownCountry = false }));
        Assert.False(GeoPolicy.IsRejected(unknown, new GeoOptions { AllowUnknownCountry = true }));
    }

    [Fact]
    public void TikTok_capability_aggregation_is_level_specific()
    {
        var capabilities = new[] {
            new TikTokCapabilityResult { Capability = TikTokCapability.TikTokHomepage, Status = TikTokCapabilityStatus.Passed },
            new TikTokCapabilityResult { Capability = TikTokCapability.TikTokPublicVideoPage, Status = TikTokCapabilityStatus.MediaUnverified }
        };
        Assert.True(TikTokCapabilityAggregator.Passed(capabilities, TikTokCapability.TikTokHomepage));
        Assert.False(TikTokCapabilityAggregator.Passed(capabilities, TikTokCapability.TikTokPublicVideoPage));
    }

    [Fact]
    public void Oembed_requires_json_and_requested_video_identity()
    {
        var url = new Uri("https://www.tiktok.com/@demo/video/1234567890");
        var body = """{"title":"demo","html":"<blockquote cite=\"https://www.tiktok.com/@demo/video/1234567890\">x</blockquote>"}""";
        Assert.Equal(TikTokCapabilityStatus.Passed, TikTokContentClassifier.ClassifyOEmbed(200, body, url));
        Assert.Equal(TikTokCapabilityStatus.InvalidContent, TikTokContentClassifier.ClassifyOEmbed(200, "{}", url));
    }

    [Fact]
    public void Stability_calculates_ratio_median_and_jitter()
    {
        var attempts = new[] {
            Attempt(1, true, 100), Attempt(2, true, 200), Attempt(3, false, 400)
        };
        var result = StabilityCalculator.Calculate(attempts, new StabilityOptions { MinimumSuccessRatio = 0.66, MaximumAllowedJitterMs = 1000 });
        Assert.Equal(2d / 3, result.SuccessRatio, 3); Assert.Equal(200, result.MedianLatencyMs); Assert.True(result.JitterMs > 0);
        Assert.Equal(ProxyStabilityStatus.Stable, result.Status);
    }

    [Fact]
    public void Updated_score_rejects_ru_and_rewards_stage2_signals()
    {
        var endpoint = Endpoint();
        var ru = new ProxyCheckResult { Endpoint = endpoint, Geo = Geo("8.8.8.8", "RU", "a") };
        Assert.Equal(0, new ProxyScorer(new ScoreWeights(), ["KZ"]).Calculate(ru).Value);
        var good = new ProxyCheckResult { Endpoint = endpoint, ExitIp = new ExitIpResolutionResult { Status = ExitIpStatus.Resolved, ExitIp = "8.8.8.8" },
            Geo = Geo("8.8.8.8", "KZ", "a"), TikTokCapabilities = [new() { Capability = TikTokCapability.TikTokHomepage, Status = TikTokCapabilityStatus.Passed }] };
        Assert.True(new ProxyScorer(new ScoreWeights(), ["KZ"]).Calculate(good).Value >= 30);
    }

    [Fact]
    public async Task Checkpoint_round_trip_and_hash_gate_resume()
    {
        var path = Path.Combine(Path.GetTempPath(), "tph-checkpoint-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var store = new RunCheckpointStore(); var hash = RunCheckpointStore.ComputeConfigurationHash("a", "b");
            await store.SaveAsync(path, new RunCheckpoint { ConfigurationHash = hash, Stage = "complete", CompletedEndpointKeys = new HashSet<string> { "one" } }, CancellationToken.None);
            var loaded = await store.LoadAsync(path, CancellationToken.None);
            Assert.True(RunCheckpointStore.CanResume(loaded, hash)); Assert.False(RunCheckpointStore.CanResume(loaded, "different"));
            Assert.Contains("one", loaded!.CompletedEndpointKeys);
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task Probe_pipeline_resume_skips_completed_endpoint()
    {
        var first = Endpoint();
        var second = first with { Host = "1.1.1.1", NormalizedKey = "socks5://1.1.1.1:1080" };
        var detector = new CountingDetector();
        var results = await new StreamingProbePipeline(detector, new HunterOptions { ProbeConcurrency = 2, ChannelCapacity = 1 })
            .ProbeAsync([first, second], new HashSet<string> { first.NormalizedKey }, CancellationToken.None);
        Assert.Single(results); Assert.Equal(second.NormalizedKey, results[0].Endpoint.NormalizedKey); Assert.Equal(1, detector.Count);
    }

    [Fact]
    public void Browser_result_requires_progress_and_allowed_media_response()
    {
        var url = new Uri("https://www.tiktok.com/@demo/video/1234567890");
        var before = new PlaywrightBrowserProxyVerifier.VideoState(3, 1, 10, 1, false);
        var after = new PlaywrightBrowserProxyVerifier.VideoState(4, 1, 10, 5, false);
        Assert.Equal(BrowserVerificationStatus.Passed, BrowserVerificationClassifier.Classify(url, before, after, 1, 3).Status);
        Assert.Equal(BrowserVerificationStatus.MediaUnverified, BrowserVerificationClassifier.Classify(url, before, after with { CurrentTime = 2 }, 1, 3).Status);
        Assert.True(PlaywrightBrowserProxyVerifier.IsAllowedMediaResponse("https://v16.tiktokcdn.com/a.mp4", "media", ["tiktokcdn.com"]));
        Assert.False(PlaywrightBrowserProxyVerifier.IsAllowedMediaResponse("https://evil.example/a.mp4", "media", ["tiktokcdn.com"]));
    }

    private static ProxySourceDefinition SourceDefinition() => new() { Name = "source", Enabled = true,
        Url = "https://example.test/proxies.txt", Format = "text", DeclaredProtocol = ProxyProtocol.Http,
        ExpectedContentType = "text/plain", MaximumDownloadBytes = 1024, MinimumExpectedCandidates = 1 };
    private static ProxyGeoInfo Geo(string ip, string code, string source) => new()
    { IpAddress = ip, Status = ProxyGeoStatus.Resolved, CountryCode = code, Sources = [source] };
    private static ProxyCheckAttempt Attempt(int number, bool success, double latency) => new()
    { Attempt = number, Success = success, Latency = TimeSpan.FromMilliseconds(latency), ExitIp = success ? "8.8.8.8" : null,
        Status = success ? TikTokCapabilityStatus.Passed : TikTokCapabilityStatus.Failed };
    private static ProxyEndpoint Endpoint() => new()
    { Host = "8.8.8.8", Port = 1080, Source = "test", Sources = ["test"], SourceFamilies = ["family"],
        NormalizedKey = "socks5://8.8.8.8:1080", DetectedProtocol = ProxyProtocol.Socks5 };

    private sealed class TestHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    { public HttpClient CreateClient(string name) => new(handler, disposeHandler: false); }
    private sealed class DelegateHandler(Func<HttpRequestMessage, HttpResponseMessage> handler) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(handler(request)); }
    private static HttpRequestMessage CloneHeaders(HttpRequestMessage request)
    {
        var clone = new HttpRequestMessage(request.Method, request.RequestUri);
        foreach (var header in request.Headers) clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        return clone;
    }
    private sealed class CountingDetector : IProxyProtocolDetector
    {
        private int _count;
        public int Count => _count;
        public Task<ProxyProbeResult> DetectAsync(ProxyEndpoint endpoint, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _count);
            return Task.FromResult(new ProxyProbeResult { Endpoint = endpoint, Success = true, Protocol = ProxyProtocol.Socks5 });
        }
    }
}
