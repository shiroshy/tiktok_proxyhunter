using TikTokProxyHunter.Core;
using TikTokProxyHunter.Infrastructure;

namespace TikTokProxyHunter.Tests;

public sealed class ParserTests
{
    private static ProxySourceDefinition Source(string format = "text", ProxyProtocol protocol = ProxyProtocol.Unknown) =>
        new() { Name = "test", Format = format, DeclaredProtocol = protocol };

    [Fact]
    public void Text_parser_supports_common_formats_and_extra_columns()
    {
        const string content = """
            8.8.8.8:80
            socks5://1.1.1.1:1080
            http://alice:s3cret@9.9.9.9:3128
            208.67.222.222,8080
            proxy.example 9000
            4.2.2.2:8888 US elite
            64.6.64.6,8118,socks4,US
            """;
        var results = new TextProxyParser().Parse(Source(), content);
        Assert.Equal(7, results.Count);
        Assert.Contains(results, x => x.Host == "1.1.1.1" && x.DeclaredProtocol == ProxyProtocol.Socks5);
        var authenticated = Assert.Single(results, x => x.Username == "alice");
        Assert.Equal("s3cret", authenticated.Password);
        Assert.Contains(results, x => x.Host == "proxy.example" && x.Port == 9000);
        Assert.Contains(results, x => x.Host == "64.6.64.6" && x.DeclaredProtocol == ProxyProtocol.Socks4);
    }

    [Fact]
    public void Parser_supports_bracketed_ipv6()
    {
        var result = Assert.Single(new TextProxyParser().Parse(Source(), "socks5://[2001:4860:4860::8888]:1080"));
        Assert.Equal("2001:4860:4860::8888", result.Host);
    }

    [Fact]
    public void Html_parser_extracts_published_ipv4_port_patterns()
    {
        var result = new HtmlProxyParser().Parse(Source("html"), "<table><tr><td>8.8.4.4:8080</td><td>US</td></tr></table>");
        Assert.Single(result);
    }

    [Fact]
    public void Json_parser_supports_known_fields_and_configured_path()
    {
        var path = System.Text.Json.JsonDocument.Parse("\"payload.items\"").RootElement.Clone();
        var source = Source("json") with { ParserOptions = new() { ["path"] = path } };
        var result = new JsonProxyParser().Parse(source, """{"payload":{"items":[{"address":"8.8.8.8","port":"1080","type":"socks5"}]}}""");
        var candidate = Assert.Single(result);
        Assert.Equal(ProxyProtocol.Socks5, candidate.DeclaredProtocol);
    }
}
