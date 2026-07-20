using TikTokProxyHunter.Core;
using TikTokProxyHunter.Infrastructure;

namespace TikTokProxyHunter.Tests;

public sealed class ClassificationAndScoreTests
{
    private static readonly ContentSignatures Signatures = new();

    [Theory]
    [InlineData(200, "www.tiktok.com", "<html>tiktok real page content ......................................................................................</html>", true, TikTokStatus.Accessible)]
    [InlineData(200, "www.tiktok.com", "<html>captcha verify you are human ...................................................................................</html>", true, TikTokStatus.CaptchaOrChallenge)]
    [InlineData(403, "www.tiktok.com", "<html>tiktok access denied .............................................................................................</html>", true, TikTokStatus.Forbidden)]
    [InlineData(429, "www.tiktok.com", "<html>tiktok rate limited ..............................................................................................</html>", true, TikTokStatus.RateLimited)]
    [InlineData(200, "evil.example", "<html>tiktok ...........................................................................................................</html>", true, TikTokStatus.InvalidContent)]
    [InlineData(200, "www.tiktok.com", "<html>tiktok ...........................................................................................................</html>", false, TikTokStatus.TlsFailure)]
    public void Classifies_tiktok_results(int code, string host, string body, bool tls, TikTokStatus expected)
    {
        Assert.Equal(expected, TikTokResultClassifier.Classify(code, host, body,
            new Dictionary<string, string>(), tls, Signatures));
    }

    [Fact]
    public void Score_uses_configured_weights()
    {
        var endpoint = Endpoint() with { DetectedProtocol = ProxyProtocol.Socks5, Sources = ["a", "b", "c"] };
        var check = new TikTokCheckResult { Url = new Uri("https://www.tiktok.com"), Status = TikTokStatus.Accessible, TlsValid = true, TotalTime = TimeSpan.FromMilliseconds(100) };
        var score = new ProxyScorer(new ScoreWeights()).Calculate(new ProxyCheckResult { Endpoint = endpoint, TikTokChecks = [check], SuccessfulChecks = 2 });
        Assert.Equal(92, score.Value);
    }

    [Fact]
    public void Tls_failure_forces_score_to_zero()
    {
        var check = new TikTokCheckResult { Url = new Uri("https://www.tiktok.com"), Status = TikTokStatus.TlsFailure };
        Assert.Equal(0, new ProxyScorer(new ScoreWeights()).Calculate(new ProxyCheckResult { Endpoint = Endpoint(), TikTokChecks = [check] }).Value);
    }

    private static ProxyEndpoint Endpoint() => new() { Host = "8.8.8.8", Port = 1080, Source = "test", Sources = ["test"], NormalizedKey = "unknown://8.8.8.8:1080" };
}
