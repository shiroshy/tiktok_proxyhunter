using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Tests;

public sealed class CoreLogicTests
{
    private static ProxyCandidate Candidate(string host, int port = 8080, string source = "one",
        ProxyProtocol protocol = ProxyProtocol.Http) => new(host, port, protocol, source, DateTimeOffset.UnixEpoch);

    [Theory]
    [InlineData("8.8.8.8", "8.8.8.8")]
    [InlineData("2001:4860:4860::8888", "2001:4860:4860::8888")]
    [InlineData("Proxy.Example.COM", "proxy.example.com")]
    public void Normalizer_accepts_public_ipv4_ipv6_and_hostname(string input, string expected)
    {
        var normalizer = new ProxyNormalizer(new NormalizationOptions());
        Assert.True(normalizer.TryNormalize(Candidate(input), out var result, out var reason), reason);
        Assert.Equal(expected, result!.Host);
        if (expected.Contains(':')) Assert.Contains($"[{expected}]:8080", result.NormalizedKey);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65536)]
    [InlineData(-1)]
    public void Normalizer_rejects_invalid_ports(int port)
    {
        Assert.False(new ProxyNormalizer(new NormalizationOptions()).TryNormalize(Candidate("8.8.8.8", port), out _, out _));
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.0.0.1")]
    [InlineData("192.168.1.1")]
    [InlineData("169.254.1.1")]
    [InlineData("224.0.0.1")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    public void Normalizer_rejects_non_public_addresses_by_default(string host)
    {
        Assert.False(new ProxyNormalizer(new NormalizationOptions()).TryNormalize(Candidate(host), out _, out _));
    }

    [Fact]
    public void Private_addresses_can_be_explicitly_allowed_but_loopback_cannot()
    {
        var normalizer = new ProxyNormalizer(new NormalizationOptions(true));
        Assert.True(normalizer.TryNormalize(Candidate("10.0.0.1"), out _, out _));
        Assert.False(normalizer.TryNormalize(Candidate("127.0.0.1"), out _, out _));
    }

    [Fact]
    public void Deduplication_merges_sources_and_observations()
    {
        var normalizer = new ProxyNormalizer(new NormalizationOptions());
        normalizer.TryNormalize(Candidate("8.8.8.8", source: "alpha"), out var first, out _);
        normalizer.TryNormalize(Candidate("8.8.8.8", source: "beta"), out var second, out _);
        var merged = Assert.Single(new ProxyDeduplicator().Deduplicate([first!, second!]));
        Assert.Equal(2, merged.Sources.Count);
        Assert.Equal(2, merged.ObservationCount);
    }

    [Fact]
    public void Deduplication_keeps_different_protocol_claims_separate()
    {
        var normalizer = new ProxyNormalizer(new NormalizationOptions());
        normalizer.TryNormalize(Candidate("8.8.8.8", protocol: ProxyProtocol.Http), out var http, out _);
        normalizer.TryNormalize(Candidate("8.8.8.8", protocol: ProxyProtocol.Socks5), out var socks, out _);
        Assert.Equal(2, new ProxyDeduplicator().Deduplicate([http!, socks!]).Count);
    }

    [Fact]
    public void Credentials_are_redacted_from_uri_and_endpoint_string()
    {
        Assert.Equal("socks5://***:***@proxy.example:1080", SensitiveData.RedactProxyUri("socks5://alice:secret@proxy.example:1080"));
        var endpoint = new ProxyEndpoint { Host = "proxy.example", Port = 1080, Source = "test", NormalizedKey = "key", Username = "alice", Password = "secret" };
        Assert.DoesNotContain("secret", endpoint.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("alice", endpoint.ToString(), StringComparison.Ordinal);
    }
}
