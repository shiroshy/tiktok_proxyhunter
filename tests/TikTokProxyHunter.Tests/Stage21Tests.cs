using TikTokProxyHunter.Core;
using TikTokProxyHunter.Infrastructure;

namespace TikTokProxyHunter.Tests;

public sealed class Stage21Tests
{
    [Fact]
    public void Country_consensus_is_independent_of_city_and_asn()
    {
        var result = Consensus(Geo("KZ", "a", "Almaty", "AS1"), Geo("KZ", "b", "Astana", "AS2"));
        Assert.Equal(GeoResolutionDecision.ConfirmedNonRussia, result.Decision);
        Assert.Equal(GeoConfidenceLevel.High, result.FieldResolutions[GeoEvidenceField.CountryCode].Confidence);
        Assert.Equal(GeoConfidenceLevel.Conflicting, result.FieldResolutions[GeoEvidenceField.Asn].Confidence);
    }

    [Fact]
    public void One_provider_and_one_unavailable_is_likely_non_russia()
    {
        var result = Consensus(Geo("FI", "a"), new ProxyGeoInfo { IpAddress = "8.8.8.8", Status = ProxyGeoStatus.Unavailable, Sources = ["b"] });
        Assert.Equal(GeoResolutionDecision.LikelyNonRussia, result.Decision);
        Assert.Equal(GeoConfidenceLevel.Low, result.ConfidenceLevel);
    }

    [Fact]
    public void Different_country_codes_are_conflicting()
    {
        var result = Consensus(Geo("DE", "a"), Geo("NL", "b"));
        Assert.Equal(GeoResolutionDecision.Conflicting, result.Decision);
        Assert.Equal(GeoConfidenceLevel.Conflicting, result.ConfidenceLevel);
    }

    [Fact]
    public void Russia_decisions_distinguish_confirmed_and_likely()
    {
        Assert.Equal(GeoResolutionDecision.ConfirmedRussia, Consensus(Geo("RU", "a"), Geo("RU", "b")).Decision);
        Assert.Equal(GeoResolutionDecision.LikelyRussia, Consensus(Geo("RU", "a")).Decision);
    }

    [Fact]
    public void Unknown_geo_can_run_fast_but_cannot_be_recommended()
    {
        var options = new GeoOptions { AllowUnknownCountryForFastCheck = true, AllowUnknownCountryForRecommendation = false };
        var unknown = new ProxyGeoInfo { IpAddress = "8.8.8.8", Decision = GeoResolutionDecision.Unknown };
        Assert.True(GeoPolicy.IsFastCheckEligible(unknown, options));
        Assert.False(GeoPolicy.IsRecommendationEligible(unknown, options));
    }

    [Fact]
    public async Task Local_geo_provider_handles_missing_file()
    {
        using var provider = new LocalGeoIpProvider(new GeoOptions { LocalDatabase = new LocalGeoDatabaseOptions
        { Enabled = true, CountryDatabasePath = "missing-country.mmdb", AsnDatabasePath = "missing-asn.mmdb" } });
        var evidence = await provider.ResolveAsync("8.8.8.8", CancellationToken.None);
        var validation = await provider.ValidateAsync(CancellationToken.None);
        Assert.True(evidence.IsError); Assert.All(validation, x => Assert.False(x.Exists));
    }

    [Fact]
    public async Task Local_geo_provider_handles_corrupt_mmdb()
    {
        var path = Path.Combine(Path.GetTempPath(), $"corrupt-{Guid.NewGuid():N}.mmdb");
        await File.WriteAllTextAsync(path, "not a maxmind database");
        try
        {
            using var provider = new LocalGeoIpProvider(new GeoOptions { LocalDatabase = new LocalGeoDatabaseOptions
            { Enabled = true, CountryDatabasePath = path } });
            var evidence = await provider.ResolveAsync("8.8.8.8", CancellationToken.None);
            var validation = await provider.ValidateAsync(CancellationToken.None);
            Assert.True(evidence.IsError); Assert.False(validation[0].FormatValid);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Pre_score_is_deterministic_and_uses_independent_families()
    {
        var scorer = new ProxyPreScorer(new ProxyPreScoreWeights());
        var endpoint = Endpoint() with { DetectedProtocol = ProxyProtocol.Socks5, SourceFamilies = ["one", "two"] };
        var check = new ProxyCheckResult { Endpoint = endpoint,
            Probe = new ProxyProbeResult { Endpoint = endpoint, Success = true, Protocol = ProxyProtocol.Socks5,
                ConnectTime = TimeSpan.FromMilliseconds(100), TunnelTime = TimeSpan.FromMilliseconds(50) } };
        Assert.Equal(scorer.Calculate(check).Value, scorer.Calculate(check).Value);
        Assert.Equal(scorer.Calculate(check).Reasons, scorer.Calculate(check).Reasons);
        Assert.True(scorer.Calculate(check).Value >= 43);
    }

    [Fact]
    public void Pipeline_limit_is_deterministic()
    {
        var input = new[] { Check("z", 10), Check("b", 20), Check("a", 20) };
        var first = DeterministicPipelineLimiter.Take(input, 2).Select(x => x.Endpoint.NormalizedKey).ToArray();
        var second = DeterministicPipelineLimiter.Take(input.Reverse(), 2).Select(x => x.Endpoint.NormalizedKey).ToArray();
        Assert.Equal(["a", "b"], first); Assert.Equal(first, second);
    }

    [Fact]
    public void Funnel_statistics_include_reasons_and_latency()
    {
        var stage = PipelineFunnelBuilder.Create(PipelineStage.ProtocolAlive, 4, 2, TimeSpan.FromSeconds(1), ["timeout", "timeout"], [100, 300]);
        Assert.Equal(2, stage.RejectedCount); Assert.Equal(2, stage.RejectionReasons["timeout"]); Assert.Equal(200, stage.MedianLatencyMs);
    }

    [Theory]
    [InlineData("http://www.tiktok.com/@a/video/12345")]
    [InlineData("https://example.com/@a/video/12345")]
    [InlineData("https://www.tiktok.com/@a/not-video/12345")]
    [InlineData("https://www.tiktok.com/@a/video/12345?access_token=secret")]
    public void Public_video_url_rejects_unsafe_values(string value) =>
        Assert.False(TikTokVideoUrlValidator.TryValidate(value, ["tiktok.com"], out _, out _));

    [Fact]
    public void Public_video_url_accepts_tiktok_https_page()
    {
        Assert.True(TikTokVideoUrlValidator.TryValidate("https://www.tiktok.com/@public/video/1234567890", ["tiktok.com"], out var uri, out _));
        Assert.Equal("www.tiktok.com", uri!.Host);
    }

    [Fact]
    public async Task Test_video_local_config_is_loaded()
    {
        var path = Path.Combine(Path.GetTempPath(), $"videos-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(path, """{"publicVideoTestUrls":["https://www.tiktok.com/@public/video/1234567890"]}""");
        try { Assert.Single(TikTokVideoFileLoader.Load(path)); } finally { File.Delete(path); }
    }

    [Fact]
    public void Browser_doctor_missing_chromium_is_explicit()
    {
        var result = BrowserDoctor.MissingChromium("install chromium");
        Assert.False(result.ChromiumInstalled); Assert.False(result.LaunchSucceeded); Assert.Contains("install chromium", result.InstallCommand);
    }

    [Fact]
    public void Explain_proxy_never_prints_password()
    {
        var endpoint = Endpoint() with { Username = "user", Password = "super-secret" };
        var text = ExplainProxyFormatter.Format(new ProxyCheckResult { Endpoint = endpoint }, new GeoOptions());
        Assert.DoesNotContain("super-secret", text); Assert.DoesNotContain("user", text);
    }

    [Fact]
    public async Task User_export_separates_unknown_country_and_credentials()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"user-export-{Guid.NewGuid():N}");
        try
        {
            var exporter = new Stage2ResultExporter();
            var recommended = Ready("recommended", GeoResolutionDecision.ConfirmedNonRussia, GeoConfidenceLevel.High);
            var unknown = Ready("unknown", GeoResolutionDecision.Unknown, GeoConfidenceLevel.Unknown);
            var secret = Ready("secret", GeoResolutionDecision.ConfirmedNonRussia, GeoConfidenceLevel.High) with
            { Endpoint = Endpoint("secret") with { Username = "alice", Password = "hidden" } };
            await exporter.ExportUserListsAsync(directory, [recommended, unknown, secret], new GeoOptions(), false, CancellationToken.None);
            var recommendedText = await File.ReadAllTextAsync(Path.Combine(directory, "recommended.txt"));
            var unknownText = await File.ReadAllTextAsync(Path.Combine(directory, "unverified-country.txt"));
            var allText = string.Join('\n', Directory.GetFiles(directory).Select(File.ReadAllText));
            Assert.Contains("recommended", recommendedText); Assert.DoesNotContain("unknown", recommendedText);
            Assert.Contains("unknown", unknownText); Assert.DoesNotContain("alice", allText); Assert.DoesNotContain("hidden", allText);
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
    }

    private static ProxyGeoInfo Consensus(params ProxyGeoInfo[] input) => new GeoConsensusService().Resolve("8.8.8.8", input, 2);
    private static ProxyGeoInfo Geo(string country, string provider, string? city = null, string? asn = null) =>
        new() { IpAddress = "8.8.8.8", Status = ProxyGeoStatus.Resolved, CountryCode = country, City = city, Asn = asn, Sources = [provider] };
    private static ProxyEndpoint Endpoint(string host = "proxy.example") => new()
    { Host = host, Port = 1080, Source = "test", NormalizedKey = host, Sources = ["test"] };
    private static ProxyCheckResult Check(string key, int score) => new() { Endpoint = Endpoint(key), PreScore = new(score, false, []) };
    private static ProxyCheckResult Ready(string host, GeoResolutionDecision decision, GeoConfidenceLevel confidence)
    {
        var endpoint = Endpoint(host) with { DetectedProtocol = ProxyProtocol.Socks5 };
        return new ProxyCheckResult { Endpoint = endpoint,
            ExitIp = new() { Status = ExitIpStatus.Resolved, ExitIp = "8.8.8.8" },
            Geo = new() { IpAddress = "8.8.8.8", CountryCode = decision == GeoResolutionDecision.Unknown ? null : "KZ", Decision = decision, ConfidenceLevel = confidence },
            Stability = new() { Status = ProxyStabilityStatus.Stable },
            TikTokCapabilities = [new() { Capability = TikTokCapability.TikTokDnsAndTunnel, Status = TikTokCapabilityStatus.Passed },
                new() { Capability = TikTokCapability.TikTokHomepage, Status = TikTokCapabilityStatus.Passed },
                new() { Capability = TikTokCapability.TikTokPublicVideoPage, Status = TikTokCapabilityStatus.Passed }] };
    }
}
