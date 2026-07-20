using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Infrastructure;

namespace TikTokProxyHunter.Tests;

public sealed class IntegrationTests
{
    [Fact]
    public async Task Http_connect_stub_is_detected()
    {
        await using var server = LocalTestServer.HttpConnect();
        var result = await Probe(server.Port, ProxyProtocol.HttpsConnect);
        Assert.True(result.Success, result.FailureReason);
        Assert.Equal(200, result.ResponseCode);
    }

    [Fact]
    public async Task Socks5_stub_is_detected()
    {
        await using var server = LocalTestServer.Socks5();
        var result = await Probe(server.Port, ProxyProtocol.Socks5);
        Assert.True(result.Success, result.FailureReason);
    }

    [Fact]
    public async Task Exit_provider_http_fallback_works_through_local_proxy_stub()
    {
        await using var server = LocalTestServer.PlainHttpEcho("{\"ip\":\"203.0.113.42\"}");
        var endpoint = Endpoint(server.Port, ProxyProtocol.Http);
        var response = await new ProxyHttpClient(new HunterOptions { TikTokRequestTimeoutSeconds = 2 })
            .GetAsync(endpoint, new Uri("http://echo.example/ip"), CancellationToken.None);
        Assert.Equal(200, response.StatusCode);
        Assert.True(ExitIpResolver.TryParseIp(response.Body, null, out var ip));
        Assert.Equal("203.0.113.42", ip);
    }

    [Fact]
    public async Task Timeout_stub_is_classified_as_failed_probe()
    {
        await using var server = LocalTestServer.Timeout();
        var result = await Probe(server.Port, ProxyProtocol.Socks5, 1);
        Assert.False(result.Success);
        Assert.Equal("Timeout", result.FailureReason);
    }

    [Fact]
    public async Task Production_checker_rejects_untrusted_tls_certificate()
    {
        using var certificate = LocalTestServer.CreateCertificate();
        await using var server = LocalTestServer.InvalidTlsConnect(certificate);
        var options = new HunterOptions { ProxyConnectTimeoutSeconds = 2, TikTokRequestTimeoutSeconds = 3 };
        var result = await new TikTokChecker(options).CheckAsync(Endpoint(server.Port, ProxyProtocol.HttpsConnect),
            new Uri("https://www.tiktok.com/"), CancellationToken.None);
        Assert.Equal(TikTokStatus.TlsFailure, result.Status);
        Assert.False(result.TlsValid);
    }

    [Theory]
    [InlineData("<html><head><title>TikTok</title></head><body>tiktok __UNIVERSAL_DATA_FOR_REHYDRATION__ ....................................................................................</body></html>", TikTokStatus.Accessible)]
    [InlineData("<html><head><title>Verify</title></head><body>captcha verify you are human ...............................................................................................</body></html>", TikTokStatus.CaptchaOrChallenge)]
    public async Task Local_tiktok_like_tls_endpoint_is_strictly_validated_and_classified(string body, TikTokStatus expected)
    {
        using var certificate = LocalTestServer.CreateCertificate();
        await using var server = LocalTestServer.TlsHtml(certificate, body);
        using var tcp = new TcpClient();
        await tcp.ConnectAsync("127.0.0.1", server.Port);
        await using var ssl = new SslStream(tcp.GetStream(), false);
        var policy = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
            DisableCertificateDownloads = true
        };
        policy.CustomTrustStore.Add(certificate);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "www.tiktok.com", EnabledSslProtocols = SslProtocols.Tls12, CertificateChainPolicy = policy
        });
        await ssl.WriteAsync("GET / HTTP/1.1\r\nHost: www.tiktok.com\r\nConnection: close\r\n\r\n"u8.ToArray());
        var response = new StringBuilder(); var buffer = new byte[4096]; int read;
        while ((read = await ssl.ReadAsync(buffer)) > 0) response.Append(Encoding.UTF8.GetString(buffer, 0, read));
        var separator = response.ToString().IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var actualBody = response.ToString()[(separator + 4)..];
        var status = TikTokResultClassifier.Classify(200, "www.tiktok.com", actualBody,
            new Dictionary<string, string>(), tlsValid: true, new ContentSignatures());
        Assert.Equal(expected, status);
    }

    private static Task<ProxyProbeResult> Probe(int port, ProxyProtocol protocol, int timeout = 2) =>
        new ProxyProbe(new HunterOptions { ProxyConnectTimeoutSeconds = timeout }, NullLogger<ProxyProbe>.Instance)
            .ProbeAsync(Endpoint(port, protocol), protocol, "www.tiktok.com", 443, CancellationToken.None);

    private static ProxyEndpoint Endpoint(int port, ProxyProtocol protocol) => new()
    {
        Host = "127.0.0.1", Port = port, Source = "local-test", Sources = ["local-test"],
        NormalizedKey = $"{protocol}://127.0.0.1:{port}", DeclaredProtocol = protocol, DetectedProtocol = protocol
    };
}
