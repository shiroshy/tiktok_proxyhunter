using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace TikTokProxyHunter.Core;

public sealed partial class ProxyNormalizer(NormalizationOptions options) : IProxyNormalizer
{
    public bool TryNormalize(ProxyCandidate candidate, out ProxyEndpoint? endpoint, out string? rejectionReason)
    {
        endpoint = null;
        var host = candidate.Host.Trim().Trim('[', ']').ToLowerInvariant();
        if (candidate.Port is < 1 or > 65535)
            return Reject("Port must be in range 1..65535", out rejectionReason);
        if (string.IsNullOrWhiteSpace(host))
            return Reject("Host is empty", out rejectionReason);

        string canonicalHost;
        if (IPAddress.TryParse(host, out var address))
        {
            if (IsForbiddenAddress(address) || (!options.AllowPrivateAddresses && IsPrivate(address)))
                return Reject("Address is non-public or prohibited by configuration", out rejectionReason);
            canonicalHost = address.ToString().ToLowerInvariant();
        }
        else
        {
            if (!IsValidHostname(host))
                return Reject("Invalid hostname", out rejectionReason);
            canonicalHost = new IdnMapping().GetAscii(host).ToLowerInvariant();
        }

        var displayHost = canonicalHost.Contains(':', StringComparison.Ordinal) ? $"[{canonicalHost}]" : canonicalHost;
        var protocol = candidate.DeclaredProtocol;
        endpoint = new ProxyEndpoint
        {
            Host = canonicalHost,
            Port = candidate.Port,
            DeclaredProtocol = protocol,
            DetectedProtocol = ProxyProtocol.Unknown,
            Source = candidate.Source,
            Sources = [candidate.Source],
            SourceFamilies = [candidate.Source],
            RetrievedAt = candidate.RetrievedAt,
            Username = candidate.Username,
            Password = candidate.Password,
            NormalizedKey = $"{protocol.ToString().ToLowerInvariant()}://{displayHost}:{candidate.Port}"
        };
        rejectionReason = null;
        return true;
    }

    private static bool Reject(string reason, out string? rejectionReason)
    {
        rejectionReason = reason;
        return false;
    }

    private static bool IsForbiddenAddress(IPAddress address) => IPAddress.IsLoopback(address)
        || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)
        || address.Equals(IPAddress.None) || address.Equals(IPAddress.IPv6None)
        || address.IsIPv6LinkLocal || address.IsIPv6Multicast
        || (address.AddressFamily == AddressFamily.InterNetwork && ((address.GetAddressBytes()[0] & 0xF0) == 0xE0));

    private static bool IsPrivate(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
            return bytes[0] == 10 || bytes[0] == 127 || (bytes[0] == 169 && bytes[1] == 254)
                || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 100 && bytes[1] is >= 64 and <= 127);
        return address.IsIPv6UniqueLocal || address.IsIPv6LinkLocal || IPAddress.IsLoopback(address);
    }

    private static bool IsValidHostname(string host) => host.Length <= 253 && HostnameRegex().IsMatch(host)
        && host.Split('.').All(label => label.Length is > 0 and <= 63 && label[0] != '-' && label[^1] != '-');

    [GeneratedRegex("^[a-z0-9.-]+$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HostnameRegex();
}

public sealed class ProxyDeduplicator : IProxyDeduplicator
{
    public IReadOnlyList<ProxyEndpoint> Deduplicate(IEnumerable<ProxyEndpoint> endpoints) => endpoints
        .GroupBy(x => (x.Host, x.Port, x.DeclaredProtocol, x.Username), EndpointKeyComparer.Instance)
        .Select(group =>
        {
            var first = group.OrderBy(x => x.RetrievedAt).First();
            var sources = group.SelectMany(x => x.Sources.Count > 0 ? x.Sources : [x.Source])
                .Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray();
            var families = group.SelectMany(x => x.SourceFamilies).Distinct(StringComparer.OrdinalIgnoreCase).Order().ToArray();
            return first with { Sources = sources, SourceFamilies = families, Source = sources[0], ObservationCount = group.Sum(x => x.ObservationCount) };
        }).OrderBy(x => x.NormalizedKey, StringComparer.Ordinal).ToArray();

    private sealed class EndpointKeyComparer : IEqualityComparer<(string Host, int Port, ProxyProtocol Protocol, string? Username)>
    {
        public static EndpointKeyComparer Instance { get; } = new();
        public bool Equals((string Host, int Port, ProxyProtocol Protocol, string? Username) x,
            (string Host, int Port, ProxyProtocol Protocol, string? Username) y) =>
            x.Port == y.Port && x.Protocol == y.Protocol
            && StringComparer.OrdinalIgnoreCase.Equals(x.Host, y.Host)
            && StringComparer.Ordinal.Equals(x.Username, y.Username);
        public int GetHashCode((string Host, int Port, ProxyProtocol Protocol, string? Username) obj) =>
            HashCode.Combine(StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Host), obj.Port, obj.Protocol,
                obj.Username is null ? 0 : StringComparer.Ordinal.GetHashCode(obj.Username));
    }
}
