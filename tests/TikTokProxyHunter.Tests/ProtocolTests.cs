using System.Text;
using TikTokProxyHunter.Infrastructure;

namespace TikTokProxyHunter.Tests;

public sealed class ProtocolTests
{
    [Theory]
    [InlineData("HTTP/1.1 200 Connection established\r\n\r\n", 200)]
    [InlineData("HTTP/1.0 407 Proxy Authentication Required\r\n\r\n", 407)]
    public void Parses_http_connect_status(string response, int expected)
    {
        Assert.True(ProtocolHandshakes.TryParseHttpConnectResponse(Encoding.ASCII.GetBytes(response), out var status));
        Assert.Equal(expected, status);
    }

    [Fact]
    public void Rejects_malformed_http_connect_response() =>
        Assert.False(ProtocolHandshakes.TryParseHttpConnectResponse("garbage\r\n"u8, out _));

    [Fact]
    public void Parses_socks5_method_and_connect_responses()
    {
        Assert.True(ProtocolHandshakes.TryParseSocks5MethodResponse([5, 0], out var method));
        Assert.Equal(0, method);
        Assert.True(ProtocolHandshakes.TryParseSocks5ConnectResponse([5, 0, 0, 1, 127, 0, 0, 1, 0, 80], out var reply, out var length));
        Assert.Equal(0, reply); Assert.Equal(10, length);
    }

    [Fact]
    public void Parses_socks4_and_socks4a_shared_response()
    {
        Assert.True(ProtocolHandshakes.TryParseSocks4Response([0, 0x5A, 0, 80, 127, 0, 0, 1], out var reply));
        Assert.Equal(0x5A, reply);
        var request = ProtocolHandshakes.BuildSocks4aRequest("www.tiktok.com", 443, null);
        Assert.Equal(4, request[0]); Assert.Contains(Encoding.ASCII.GetBytes("www.tiktok.com"), request);
    }
}
