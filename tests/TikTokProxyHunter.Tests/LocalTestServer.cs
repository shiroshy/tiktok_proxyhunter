using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TikTokProxyHunter.Tests;

internal sealed class LocalTestServer : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly Func<TcpClient, CancellationToken, Task> _handler;
    private readonly Task _loop;
    public Exception? LastError { get; private set; }

    public LocalTestServer(Func<TcpClient, CancellationToken, Task> handler)
    {
        _handler = handler;
        _listener.Start();
        _loop = AcceptLoopAsync();
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                _ = HandleSafelyAsync(client);
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (_stop.IsCancellationRequested) { }
    }

    private async Task HandleSafelyAsync(TcpClient client)
    {
        using (client)
        {
            try { await _handler(client, _stop.Token); }
            catch (Exception ex) when (_stop.IsCancellationRequested && ex is OperationCanceledException or IOException or ObjectDisposedException) { }
            catch (AuthenticationException ex) { LastError = ex; }
            catch (IOException ex) { LastError = ex; }
        }
    }

    public static LocalTestServer HttpConnect(int status = 200) => new(async (client, token) =>
    {
        var stream = client.GetStream();
        await ReadHeadersAsync(stream, token);
        await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {status} {(status == 200 ? "Connection established" : "Rejected")}\r\n\r\n"), token);
    });

    public static LocalTestServer PlainHttpEcho(string body) => new(async (client, token) =>
    {
        var stream = client.GetStream(); await ReadHeadersAsync(stream, token);
        var response = Encoding.UTF8.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}");
        await stream.WriteAsync(response, token);
    });

    public static LocalTestServer Socks5() => new(async (client, token) =>
    {
        var stream = client.GetStream();
        var greeting = await ReadExactAsync(stream, 2, token);
        await ReadExactAsync(stream, greeting[1], token);
        await stream.WriteAsync(new byte[] { 5, 0 }, token);
        var prefix = await ReadExactAsync(stream, 4, token);
        var addressLength = prefix[3] switch { 1 => 4, 4 => 16, 3 => (await ReadExactAsync(stream, 1, token))[0], _ => 0 };
        await ReadExactAsync(stream, addressLength + 2, token);
        await stream.WriteAsync(new byte[] { 5, 0, 0, 1, 127, 0, 0, 1, 0, 80 }, token);
    });

    public static LocalTestServer Timeout() => new(async (_, token) => await Task.Delay(System.Threading.Timeout.InfiniteTimeSpan, token));

    public static LocalTestServer InvalidTlsConnect(X509Certificate2 certificate) => new(async (client, token) =>
    {
        var stream = client.GetStream();
        await ReadHeadersAsync(stream, token);
        await stream.WriteAsync("HTTP/1.1 200 Connection established\r\n\r\n"u8.ToArray(), token);
        await using var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
        await ssl.AuthenticateAsServerAsync(certificate, clientCertificateRequired: false, SslProtocols.Tls12, checkCertificateRevocation: false);
    });

    public static LocalTestServer TlsHtml(X509Certificate2 certificate, string body) => new(async (client, token) =>
    {
        await using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
        await ssl.AuthenticateAsServerAsync(certificate, clientCertificateRequired: false, SslProtocols.Tls12, checkCertificateRevocation: false);
        await ReadHeadersAsync(ssl, token);
        var response = Encoding.UTF8.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}");
        await ssl.WriteAsync(response, token);
    });

    public static X509Certificate2 CreateCertificate(string dnsName = "www.tiktok.com")
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={dnsName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        var san = new SubjectAlternativeNameBuilder(); san.AddDnsName(dnsName); request.CertificateExtensions.Add(san.Build());
        using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        const string password = "local-test-only";
        return X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx, password), password,
            X509KeyStorageFlags.Exportable);
    }

    private static async Task ReadHeadersAsync(Stream stream, CancellationToken token)
    {
        var last = new Queue<byte>(4); var buffer = new byte[1];
        while (await stream.ReadAsync(buffer, token) > 0)
        {
            if (last.Count == 4) last.Dequeue(); last.Enqueue(buffer[0]);
            if (last.SequenceEqual("\r\n\r\n"u8.ToArray())) return;
        }
    }

    private static async Task<byte[]> ReadExactAsync(Stream stream, int count, CancellationToken token)
    {
        var result = new byte[count]; var offset = 0;
        while (offset < count)
        {
            var read = await stream.ReadAsync(result.AsMemory(offset), token);
            if (read == 0) throw new EndOfStreamException(); offset += read;
        }
        return result;
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        _listener.Stop();
        try { await _loop; } catch (OperationCanceledException) { }
        _stop.Dispose();
    }
}
