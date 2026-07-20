using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace TikTokProxyHunter.Infrastructure;

public static class ProtocolHandshakes
{
    public static bool TryParseHttpConnectResponse(ReadOnlySpan<byte> response, out int statusCode)
    {
        statusCode = 0;
        var firstLineEnd = response.IndexOf("\r\n"u8);
        if (firstLineEnd < 0) return false;
        var firstLine = Encoding.ASCII.GetString(response[..firstLineEnd]);
        var parts = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2 && parts[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase)
            && int.TryParse(parts[1], out statusCode) && statusCode is >= 100 and <= 599;
    }

    public static bool TryParseSocks5MethodResponse(ReadOnlySpan<byte> response, out byte method) =>
        (method = response.Length >= 2 ? response[1] : (byte)0xFF) != 0xFF && response.Length >= 2 && response[0] == 0x05;

    public static bool TryParseSocks5ConnectResponse(ReadOnlySpan<byte> response, out byte replyCode, out int totalLength)
    {
        replyCode = response.Length >= 2 ? response[1] : (byte)0xFF;
        totalLength = 0;
        if (response.Length < 5 || response[0] != 0x05 || response[2] != 0x00) return false;
        var addressLength = response[3] switch
        {
            0x01 => 4,
            0x04 => 16,
            0x03 when response.Length >= 5 => response[4] + 1,
            _ => -1
        };
        if (addressLength < 0) return false;
        totalLength = 4 + addressLength + 2;
        return response.Length >= totalLength;
    }

    public static bool TryParseSocks4Response(ReadOnlySpan<byte> response, out byte replyCode)
    {
        replyCode = response.Length >= 2 ? response[1] : (byte)0;
        return response.Length >= 8 && response[0] == 0x00 && replyCode is >= 0x5A and <= 0x5D;
    }

    public static byte[] BuildSocks5ConnectRequest(string targetHost, int targetPort)
    {
        var bytes = new List<byte> { 0x05, 0x01, 0x00 };
        if (IPAddress.TryParse(targetHost, out var ip))
        {
            bytes.Add(ip.AddressFamily == AddressFamily.InterNetwork ? (byte)0x01 : (byte)0x04);
            bytes.AddRange(ip.GetAddressBytes());
        }
        else
        {
            var hostBytes = Encoding.ASCII.GetBytes(targetHost);
            if (hostBytes.Length > 255) throw new ArgumentOutOfRangeException(nameof(targetHost), "SOCKS5 host is too long");
            bytes.Add(0x03); bytes.Add((byte)hostBytes.Length); bytes.AddRange(hostBytes);
        }
        bytes.Add((byte)(targetPort >> 8)); bytes.Add((byte)targetPort);
        return bytes.ToArray();
    }

    public static byte[] BuildSocks4Request(IPAddress address, int targetPort, string? userId)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork) throw new ArgumentException("SOCKS4 requires IPv4", nameof(address));
        var bytes = new List<byte> { 0x04, 0x01, (byte)(targetPort >> 8), (byte)targetPort };
        bytes.AddRange(address.GetAddressBytes());
        bytes.AddRange(Encoding.ASCII.GetBytes(userId ?? string.Empty)); bytes.Add(0x00);
        return bytes.ToArray();
    }

    public static byte[] BuildSocks4aRequest(string targetHost, int targetPort, string? userId)
    {
        var bytes = new List<byte> { 0x04, 0x01, (byte)(targetPort >> 8), (byte)targetPort, 0, 0, 0, 1 };
        bytes.AddRange(Encoding.ASCII.GetBytes(userId ?? string.Empty)); bytes.Add(0x00);
        bytes.AddRange(Encoding.ASCII.GetBytes(targetHost)); bytes.Add(0x00);
        return bytes.ToArray();
    }
}
