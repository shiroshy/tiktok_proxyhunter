using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using Microsoft.Extensions.Logging;
using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Infrastructure;

public sealed class ProxyProtocolDetector(IProxyProbe probe, HunterOptions options) : IProxyProtocolDetector
{
    public async Task<ProxyProbeResult> DetectAsync(ProxyEndpoint endpoint, CancellationToken cancellationToken)
    {
        ProxyProbeResult? last = null;
        foreach (var protocol in options.ProtocolDetectionOrder.Distinct())
        {
            last = await probe.ProbeAsync(endpoint, protocol, "www.tiktok.com", 443, cancellationToken);
            if (last.Success) return last;
        }
        return last ?? new ProxyProbeResult { Endpoint = endpoint, FailureReason = "No protocols configured" };
    }
}

public sealed class ProxyProbe(HunterOptions options, ILogger<ProxyProbe> logger) : IProxyProbe
{
    public async Task<ProxyProbeResult> ProbeAsync(ProxyEndpoint endpoint, ProxyProtocol protocol,
        string targetHost, int targetPort, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(options.ProxyConnectTimeoutSeconds));
        var stopwatch = Stopwatch.StartNew();
        try
        {
            if (protocol == ProxyProtocol.Http)
                return await ProbePlainHttpAsync(endpoint, stopwatch, timeout.Token);
            var connection = await ProxyTunnelFactory.ConnectAsync(endpoint, protocol, targetHost, targetPort, timeout.Token);
            await using (connection.Stream)
            {
                return new ProxyProbeResult
                {
                    Endpoint = endpoint, Success = true, Protocol = protocol,
                    ConnectTime = connection.ConnectTime, TunnelTime = connection.TunnelTime,
                    ResponseCode = connection.ResponseCode
                };
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or InvalidDataException
            or AuthenticationException or OperationCanceledException)
        {
            logger.LogDebug("Probe failed for {Host}:{Port} as {Protocol}: {Reason}", endpoint.Host, endpoint.Port, protocol, ex.Message);
            return new ProxyProbeResult
            {
                Endpoint = endpoint, Protocol = protocol, ConnectTime = stopwatch.Elapsed,
                FailureReason = ex is OperationCanceledException ? "Timeout" : ex.Message
            };
        }
    }

    private static async Task<ProxyProbeResult> ProbePlainHttpAsync(ProxyEndpoint endpoint, Stopwatch stopwatch, CancellationToken cancellationToken)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(endpoint.Host, endpoint.Port, cancellationToken);
        var connectTime = stopwatch.Elapsed;
        await using var stream = client.GetStream();
        var request = "HEAD http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"u8.ToArray();
        await stream.WriteAsync(request, cancellationToken);
        var header = await ReadHeadersAsync(stream, 16_384, cancellationToken);
        var valid = ProtocolHandshakes.TryParseHttpConnectResponse(header, out var status);
        return new ProxyProbeResult
        {
            Endpoint = endpoint, Protocol = ProxyProtocol.Http, Success = valid,
            ConnectTime = connectTime, TunnelTime = stopwatch.Elapsed - connectTime,
            ResponseCode = valid ? status : null, FailureReason = valid ? null : "Invalid HTTP proxy response"
        };
    }

    internal static async Task<byte[]> ReadHeadersAsync(Stream stream, int maxBytes, CancellationToken cancellationToken)
    {
        var result = new List<byte>(512);
        var one = new byte[1];
        while (result.Count < maxBytes)
        {
            var read = await stream.ReadAsync(one, cancellationToken);
            if (read == 0) break;
            result.Add(one[0]);
            if (result.Count >= 4 && result[^4] == '\r' && result[^3] == '\n' && result[^2] == '\r' && result[^1] == '\n') break;
        }
        return result.ToArray();
    }
}

public sealed record ProxyTunnel(Stream Stream, TimeSpan ConnectTime, TimeSpan TunnelTime, int? ResponseCode);

public static class ProxyTunnelFactory
{
    public static async Task<ProxyTunnel> ConnectAsync(ProxyEndpoint endpoint, ProxyProtocol protocol,
        string targetHost, int targetPort, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var client = new TcpClient();
        try
        {
            await client.ConnectAsync(endpoint.Host, endpoint.Port, cancellationToken);
            var connectTime = stopwatch.Elapsed;
            var stream = client.GetStream();
            int? responseCode = protocol switch
            {
                ProxyProtocol.Socks5 => await Socks5Async(stream, endpoint, targetHost, targetPort, cancellationToken),
                ProxyProtocol.Socks4a => await Socks4aAsync(stream, endpoint, targetHost, targetPort, cancellationToken),
                ProxyProtocol.Socks4 => await Socks4Async(stream, endpoint, targetHost, targetPort, cancellationToken),
                ProxyProtocol.HttpsConnect => await HttpConnectAsync(stream, endpoint, targetHost, targetPort, cancellationToken),
                _ => throw new InvalidDataException($"Protocol {protocol} cannot create an HTTPS tunnel")
            };
            return new ProxyTunnel(new OwnedNetworkStream(client, stream), connectTime, stopwatch.Elapsed - connectTime, responseCode);
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private static async Task<int?> HttpConnectAsync(Stream stream, ProxyEndpoint endpoint, string host, int port, CancellationToken token)
    {
        var auth = string.IsNullOrEmpty(endpoint.Username) ? string.Empty
            : $"Proxy-Authorization: Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{endpoint.Username}:{endpoint.Password}"))}\r\n";
        var request = Encoding.ASCII.GetBytes($"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: keep-alive\r\n{auth}\r\n");
        await stream.WriteAsync(request, token);
        var response = await ProxyProbe.ReadHeadersAsync(stream, 32_768, token);
        if (!ProtocolHandshakes.TryParseHttpConnectResponse(response, out var status)) throw new InvalidDataException("Malformed HTTP CONNECT response");
        if (status is < 200 or > 299) throw new InvalidDataException(status == 407 ? "Proxy authentication required" : $"HTTP CONNECT rejected ({status})");
        return status;
    }

    private static async Task<int?> Socks5Async(Stream stream, ProxyEndpoint endpoint, string host, int port, CancellationToken token)
    {
        var hasCredentials = !string.IsNullOrEmpty(endpoint.Username);
        var greeting = hasCredentials ? new byte[] { 5, 2, 0, 2 } : new byte[] { 5, 1, 0 };
        await stream.WriteAsync(greeting, token);
        var methodResponse = await ReadExactAsync(stream, 2, token);
        if (!ProtocolHandshakes.TryParseSocks5MethodResponse(methodResponse, out var method)) throw new InvalidDataException("SOCKS5 authentication method rejected");
        if (method == 2)
        {
            if (!hasCredentials) throw new InvalidDataException("SOCKS5 requires authentication");
            var user = Encoding.UTF8.GetBytes(endpoint.Username!); var pass = Encoding.UTF8.GetBytes(endpoint.Password ?? string.Empty);
            if (user.Length > 255 || pass.Length > 255) throw new InvalidDataException("SOCKS5 credentials are too long");
            var auth = new byte[3 + user.Length + pass.Length]; auth[0] = 1; auth[1] = (byte)user.Length;
            user.CopyTo(auth, 2); auth[2 + user.Length] = (byte)pass.Length; pass.CopyTo(auth, 3 + user.Length);
            await stream.WriteAsync(auth, token);
            var authResponse = await ReadExactAsync(stream, 2, token);
            if (authResponse[0] != 1 || authResponse[1] != 0) throw new InvalidDataException("SOCKS5 authentication failed");
        }
        else if (method != 0) throw new InvalidDataException($"Unsupported SOCKS5 authentication method {method}");

        await stream.WriteAsync(ProtocolHandshakes.BuildSocks5ConnectRequest(host, port), token);
        var prefix = await ReadExactAsync(stream, 5, token);
        var remaining = prefix[3] switch { 1 => 5, 4 => 17, 3 => prefix[4] + 2, _ => throw new InvalidDataException("Unknown SOCKS5 address type") };
        var full = prefix.Concat(await ReadExactAsync(stream, remaining, token)).ToArray();
        if (!ProtocolHandshakes.TryParseSocks5ConnectResponse(full, out var reply, out _) || reply != 0)
            throw new InvalidDataException($"SOCKS5 CONNECT failed with code {reply}");
        return reply;
    }

    private static async Task<int?> Socks4aAsync(Stream stream, ProxyEndpoint endpoint, string host, int port, CancellationToken token)
    {
        await stream.WriteAsync(ProtocolHandshakes.BuildSocks4aRequest(host, port, endpoint.Username), token);
        return await ReadSocks4ReplyAsync(stream, token);
    }

    private static async Task<int?> Socks4Async(Stream stream, ProxyEndpoint endpoint, string host, int port, CancellationToken token)
    {
        IPAddress address;
        if (!IPAddress.TryParse(host, out address!))
            address = (await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, token)).FirstOrDefault()
                ?? throw new SocketException((int)SocketError.HostNotFound);
        await stream.WriteAsync(ProtocolHandshakes.BuildSocks4Request(address, port, endpoint.Username), token);
        return await ReadSocks4ReplyAsync(stream, token);
    }

    private static async Task<int?> ReadSocks4ReplyAsync(Stream stream, CancellationToken token)
    {
        var response = await ReadExactAsync(stream, 8, token);
        if (!ProtocolHandshakes.TryParseSocks4Response(response, out var reply) || reply != 0x5A)
            throw new InvalidDataException($"SOCKS4 CONNECT failed with code {reply}");
        return reply;
    }

    private static async Task<byte[]> ReadExactAsync(Stream stream, int count, CancellationToken token)
    {
        var buffer = new byte[count]; var offset = 0;
        while (offset < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset), token);
            if (read == 0) throw new EndOfStreamException("Proxy closed the connection during handshake");
            offset += read;
        }
        return buffer;
    }

    private sealed class OwnedNetworkStream(TcpClient owner, NetworkStream inner) : Stream
    {
        public override bool CanRead => inner.CanRead; public override bool CanSeek => false; public override bool CanWrite => inner.CanWrite;
        public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => inner.Flush(); public override Task FlushAsync(CancellationToken token) => inner.FlushAsync(token);
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default) => inner.ReadAsync(buffer, token);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException(); public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default) => inner.WriteAsync(buffer, token);
        protected override void Dispose(bool disposing) { if (disposing) { inner.Dispose(); owner.Dispose(); } base.Dispose(disposing); }
        public override async ValueTask DisposeAsync() { await inner.DisposeAsync(); owner.Dispose(); GC.SuppressFinalize(this); }
    }
}
