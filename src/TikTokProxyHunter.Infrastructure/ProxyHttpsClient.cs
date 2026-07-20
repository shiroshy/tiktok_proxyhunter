using System.Diagnostics;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Infrastructure;

public sealed record ProxyHttpResponse(int StatusCode, IReadOnlyDictionary<string, string> Headers, string Body,
    TimeSpan TotalTime, bool TlsValid);

public sealed class ProxyHttpsClient(HunterOptions options)
{
    public async Task<ProxyHttpResponse> GetAsync(ProxyEndpoint endpoint, Uri url, CancellationToken cancellationToken,
        int maximumBytes = 1_048_576)
    {
        if (!url.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Only HTTPS is supported", nameof(url));
        if (endpoint.DetectedProtocol == ProxyProtocol.Http) throw new NotSupportedException("Plain HTTP proxy cannot create a verified HTTPS tunnel");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(options.TikTokRequestTimeoutSeconds));
        var watch = Stopwatch.StartNew();
        var tunnel = await ProxyTunnelFactory.ConnectAsync(endpoint, endpoint.DetectedProtocol, url.Host, url.Port, timeout.Token);
        await using var tunnelStream = tunnel.Stream;
        await using var ssl = new SslStream(tunnelStream, false);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = url.Host,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.Online
        }, timeout.Token);
        var path = string.IsNullOrEmpty(url.PathAndQuery) ? "/" : url.PathAndQuery;
        var request = Encoding.ASCII.GetBytes($"GET {path} HTTP/1.1\r\nHost: {url.Host}\r\nUser-Agent: {options.UserAgent}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n");
        await ssl.WriteAsync(request, timeout.Token);
        await ssl.FlushAsync(timeout.Token);
        var bytes = new List<byte>(32_768); var buffer = new byte[16_384];
        while (bytes.Count <= maximumBytes + 65_536)
        {
            var read = await ssl.ReadAsync(buffer, timeout.Token);
            if (read == 0) break;
            bytes.AddRange(buffer.AsSpan(0, read).ToArray());
        }
        var separator = bytes.ToArray().AsSpan().IndexOf("\r\n\r\n"u8);
        if (separator < 0) throw new InvalidDataException("Malformed HTTPS response");
        var headerText = Encoding.ASCII.GetString(bytes.ToArray(), 0, separator);
        var lines = headerText.Split("\r\n", StringSplitOptions.None);
        var statusParts = lines[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (statusParts.Length < 2 || !int.TryParse(statusParts[1], out var status)) throw new InvalidDataException("Malformed HTTPS status line");
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1))
        {
            var colon = line.IndexOf(':'); if (colon > 0) headers[line[..colon].Trim()] = line[(colon + 1)..].Trim();
        }
        var bodyBytes = bytes.Skip(separator + 4).Take(maximumBytes).ToArray();
        if (headers.TryGetValue("transfer-encoding", out var transfer) && transfer.Contains("chunked", StringComparison.OrdinalIgnoreCase))
            bodyBytes = DecodeChunked(bodyBytes, maximumBytes);
        return new ProxyHttpResponse(status, headers, Encoding.UTF8.GetString(bodyBytes), watch.Elapsed, true);
    }

    private static byte[] DecodeChunked(byte[] input, int max)
    {
        using var output = new MemoryStream(); var position = 0;
        while (position < input.Length && output.Length < max)
        {
            var lineEnd = input.AsSpan(position).IndexOf("\r\n"u8);
            if (lineEnd < 0) break;
            var sizeText = Encoding.ASCII.GetString(input, position, lineEnd).Split(';')[0];
            if (!int.TryParse(sizeText, System.Globalization.NumberStyles.HexNumber, null, out var size) || size == 0) break;
            position += lineEnd + 2;
            if (position + size > input.Length) break;
            output.Write(input, position, Math.Min(size, max - (int)output.Length));
            position += size + 2;
        }
        return output.ToArray();
    }
}

/// <summary>Performs a bounded plain HTTP request through a detected proxy protocol for exit-IP fallback only.</summary>
public sealed class ProxyHttpClient(HunterOptions options)
{
    public async Task<ProxyHttpResponse> GetAsync(ProxyEndpoint endpoint, Uri url, CancellationToken cancellationToken,
        int maximumBytes = 16_384)
    {
        if (url.Scheme != Uri.UriSchemeHttp) throw new ArgumentException("Only HTTP is supported", nameof(url));
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(options.TikTokRequestTimeoutSeconds));
        var watch = Stopwatch.StartNew();
        if (endpoint.DetectedProtocol == ProxyProtocol.Http)
        {
            using var client = new TcpClient();
            await client.ConnectAsync(endpoint.Host, endpoint.Port, timeout.Token);
            await using var stream = client.GetStream();
            return await ExchangeAsync(stream, endpoint, url, true, maximumBytes, watch, timeout.Token);
        }
        var tunnel = await ProxyTunnelFactory.ConnectAsync(endpoint, endpoint.DetectedProtocol, url.Host,
            url.IsDefaultPort ? 80 : url.Port, timeout.Token);
        await using var tunnelStream = tunnel.Stream;
        return await ExchangeAsync(tunnelStream, endpoint, url, false, maximumBytes, watch, timeout.Token);
    }

    private async Task<ProxyHttpResponse> ExchangeAsync(Stream stream, ProxyEndpoint endpoint, Uri url,
        bool absoluteForm, int maximumBytes, Stopwatch watch, CancellationToken token)
    {
        var target = absoluteForm ? url.AbsoluteUri : string.IsNullOrEmpty(url.PathAndQuery) ? "/" : url.PathAndQuery;
        var proxyAuth = absoluteForm && !string.IsNullOrWhiteSpace(endpoint.Username)
            ? $"Proxy-Authorization: Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{endpoint.Username}:{endpoint.Password}"))}\r\n" : string.Empty;
        var request = Encoding.ASCII.GetBytes($"GET {target} HTTP/1.1\r\nHost: {url.Host}\r\nUser-Agent: {options.UserAgent}\r\nAccept: */*\r\nAccept-Encoding: identity\r\n{proxyAuth}Connection: close\r\n\r\n");
        await stream.WriteAsync(request, token); await stream.FlushAsync(token);
        var bytes = new List<byte>(4096); var buffer = new byte[4096];
        while (bytes.Count <= maximumBytes + 32_768)
        {
            var read = await stream.ReadAsync(buffer, token); if (read == 0) break;
            bytes.AddRange(buffer.AsSpan(0, read).ToArray());
        }
        var array = bytes.ToArray(); var separator = array.AsSpan().IndexOf("\r\n\r\n"u8);
        if (separator < 0) throw new InvalidDataException("Malformed HTTP response");
        var lines = Encoding.ASCII.GetString(array, 0, separator).Split("\r\n", StringSplitOptions.None);
        var parts = lines[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !int.TryParse(parts[1], out var status)) throw new InvalidDataException("Malformed HTTP status line");
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1)) { var colon = line.IndexOf(':'); if (colon > 0) headers[line[..colon].Trim()] = line[(colon + 1)..].Trim(); }
        return new(status, headers, Encoding.UTF8.GetString(array.Skip(separator + 4).Take(maximumBytes).ToArray()), watch.Elapsed, false);
    }
}
