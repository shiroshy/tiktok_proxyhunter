using System.Diagnostics;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Infrastructure;

public sealed class TikTokChecker(HunterOptions options) : ITikTokChecker
{
    public async Task<TikTokCheckResult> CheckAsync(ProxyEndpoint endpoint, Uri url, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(options.TikTokRequestTimeoutSeconds));
        var total = Stopwatch.StartNew();
        try
        {
            var current = url;
            for (var redirect = 0; redirect <= 5; redirect++)
            {
                var response = await SendOneAsync(endpoint, current, timeout.Token);
                if (response.StatusCode is >= 300 and <= 399 && response.Headers.TryGetValue("location", out var location))
                {
                    if (!Uri.TryCreate(current, location, out var next))
                        return Build(response, current, TikTokStatus.InvalidContent, total.Elapsed, "Invalid redirect URL");
                    if (!next.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                        return Build(response, next, TikTokStatus.InvalidContent, total.Elapsed, "HTTPS downgrade detected");
                    if (!TikTokResultClassifier.IsTikTokHost(next.Host))
                        return Build(response, next, TikTokStatus.InvalidContent, total.Elapsed, "Redirect to an unexpected domain");
                    current = next;
                    continue;
                }
                var status = TikTokResultClassifier.Classify(response.StatusCode, current.Host,
                    response.Body, response.Headers, tlsValid: true, options.Signatures);
                return Build(response, current, status, total.Elapsed, status == TikTokStatus.Accessible ? null : "Response did not meet Accessible criteria");
            }
            return new TikTokCheckResult { Url = url, Status = TikTokStatus.InvalidContent, TotalTime = total.Elapsed, FailureReason = "Too many redirects" };
        }
        catch (AuthenticationException ex)
        {
            return new TikTokCheckResult { Url = url, Status = TikTokStatus.TlsFailure, TotalTime = total.Elapsed, FailureReason = ex.Message };
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            return new TikTokCheckResult { Url = url, Status = TikTokStatus.Timeout, TotalTime = total.Elapsed, FailureReason = ex.Message };
        }
        catch (Exception ex) when (ex is IOException or System.Net.Sockets.SocketException or InvalidDataException)
        {
            var status = ex.Message.Contains("authentication required", StringComparison.OrdinalIgnoreCase)
                ? TikTokStatus.ProxyAuthenticationRequired : TikTokStatus.ConnectionFailure;
            return new TikTokCheckResult { Url = url, Status = status, TotalTime = total.Elapsed, FailureReason = ex.Message };
        }
    }

    private async Task<RawHttpsResponse> SendOneAsync(ProxyEndpoint endpoint, Uri url, CancellationToken token)
    {
        var tunnel = await ProxyTunnelFactory.ConnectAsync(endpoint, endpoint.DetectedProtocol, url.Host, 443, token);
        await using var tunnelStream = tunnel.Stream;
        await using var ssl = new SslStream(tunnelStream, leaveInnerStreamOpen: false);
        var tlsWatch = Stopwatch.StartNew();
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = url.Host,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.Online
        }, token);
        var tlsTime = tlsWatch.Elapsed;

        var path = string.IsNullOrEmpty(url.PathAndQuery) ? "/" : url.PathAndQuery;
        var request = Encoding.ASCII.GetBytes($"GET {path} HTTP/1.1\r\nHost: {url.Host}\r\nUser-Agent: {options.UserAgent}\r\nAccept: text/html,application/xhtml+xml\r\nAccept-Language: en-US,en;q=0.8\r\nConnection: close\r\n\r\n");
        await ssl.WriteAsync(request, token);
        await ssl.FlushAsync(token);

        var firstByteWatch = Stopwatch.StartNew();
        var first = new byte[1];
        var firstRead = await ssl.ReadAsync(first, token);
        var ttfb = firstByteWatch.Elapsed;
        if (firstRead == 0) throw new EndOfStreamException("TLS peer returned an empty response");
        var responseBytes = new List<byte>(32_768) { first[0] };
        var buffer = new byte[16_384];
        while (responseBytes.Count < 2_000_000)
        {
            var read = await ssl.ReadAsync(buffer, token);
            if (read == 0) break;
            responseBytes.AddRange(buffer.AsSpan(0, Math.Min(read, 2_000_000 - responseBytes.Count)).ToArray());
        }
        return ParseResponse(responseBytes.ToArray(), tunnel, tlsTime, ttfb);
    }

    private static RawHttpsResponse ParseResponse(byte[] bytes, ProxyTunnel tunnel, TimeSpan tlsTime, TimeSpan ttfb)
    {
        var separator = bytes.AsSpan().IndexOf("\r\n\r\n"u8);
        if (separator < 0) throw new InvalidDataException("Malformed HTTPS response headers");
        var headerText = Encoding.ASCII.GetString(bytes, 0, separator);
        var lines = headerText.Split("\r\n", StringSplitOptions.None);
        var statusParts = lines[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (statusParts.Length < 2 || !int.TryParse(statusParts[1], out var status)) throw new InvalidDataException("Malformed HTTPS status line");
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1))
        {
            var colon = line.IndexOf(':');
            if (colon > 0) headers[line[..colon].Trim()] = line[(colon + 1)..].Trim();
        }
        var bodyOffset = separator + 4;
        var body = Encoding.UTF8.GetString(bytes, bodyOffset, bytes.Length - bodyOffset);
        return new RawHttpsResponse(status, headers, body, bytes.Length - bodyOffset,
            tunnel.ConnectTime, tunnel.TunnelTime, tlsTime, ttfb);
    }

    private static TikTokCheckResult Build(RawHttpsResponse response, Uri finalUri, TikTokStatus status, TimeSpan total, string? reason) => new()
    {
        Url = finalUri, Status = status, TlsValid = true, ConnectionTime = response.ConnectionTime,
        TunnelTime = response.TunnelTime, TlsHandshakeTime = response.TlsTime, TimeToFirstByte = response.TimeToFirstByte,
        TotalTime = total, HttpStatus = response.StatusCode, ResponseBytes = response.BodyBytes,
        FinalHost = finalUri.Host, ResponseHeaders = response.Headers, FailureReason = reason
    };

    private sealed record RawHttpsResponse(int StatusCode, IReadOnlyDictionary<string, string> Headers, string Body,
        long BodyBytes, TimeSpan ConnectionTime, TimeSpan TunnelTime, TimeSpan TlsTime, TimeSpan TimeToFirstByte);
}

public static class TikTokResultClassifier
{
    public static TikTokStatus Classify(int statusCode, string finalHost, string body,
        IReadOnlyDictionary<string, string> headers, bool tlsValid, ContentSignatures signatures)
    {
        if (!tlsValid) return TikTokStatus.TlsFailure;
        if (!IsTikTokHost(finalHost)) return TikTokStatus.InvalidContent;
        if (statusCode == 407) return TikTokStatus.ProxyAuthenticationRequired;
        if (statusCode == 429) return TikTokStatus.RateLimited;
        if (statusCode == 403) return TikTokStatus.Forbidden;
        if (ContainsAny(body, signatures.Captcha) || ContainsAny(body, signatures.Challenge)) return TikTokStatus.CaptchaOrChallenge;
        if (ContainsAny(body, signatures.AccessDenied)) return TikTokStatus.AccessibleButBlocked;
        if (ContainsAny(body, signatures.ProxyError)) return TikTokStatus.InvalidContent;
        if (headers.Keys.Any(key => signatures.SuspiciousHeaders.Any(x => key.Equals(x, StringComparison.OrdinalIgnoreCase))))
            return TikTokStatus.InvalidContent;
        if (statusCode is < 200 or >= 400) return TikTokStatus.AccessibleButBlocked;
        if (body.Length < 100 || !body.Contains("<html", StringComparison.OrdinalIgnoreCase)) return TikTokStatus.InvalidContent;
        return ContainsAny(body, signatures.TikTokMarkers) ? TikTokStatus.Accessible : TikTokStatus.InvalidContent;
    }

    public static bool IsTikTokHost(string host) => host.Equals("tiktok.com", StringComparison.OrdinalIgnoreCase)
        || host.EndsWith(".tiktok.com", StringComparison.OrdinalIgnoreCase);

    private static bool ContainsAny(string value, IEnumerable<string> signatures) =>
        signatures.Any(x => !string.IsNullOrWhiteSpace(x) && value.Contains(x, StringComparison.OrdinalIgnoreCase));
}
