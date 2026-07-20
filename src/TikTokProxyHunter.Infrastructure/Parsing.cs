using System.Text.Json;
using System.Text.RegularExpressions;
using AngleSharp.Html.Parser;
using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Infrastructure;

public abstract class LineProxyParser : IProxyParser
{
    private static readonly Regex UriPattern = new(
        @"(?<scheme>https?|socks4a?|socks5)://(?:(?<user>[^\s:/@]+):(?<pass>[^\s@]*)@)?(?<host>\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+):(?<port>\d{1,5})",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    private static readonly Regex HostPortPattern = new(
        @"(?<![\w.-])(?<host>\[[0-9a-fA-F:]+\]|(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?):(?<port>\d{1,5})(?!\d)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex ColumnsPattern = new(
        @"^\s*(?<host>\[[0-9a-fA-F:]+\]|[^,\s]+)[,\s]+(?<port>\d{1,5})(?:[,\s]+(?<protocol>https?|socks4a?|socks5))?",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    public abstract bool CanParse(string format);
    public virtual IReadOnlyList<ProxyCandidate> Parse(ProxySourceDefinition source, string content) =>
        ParseLines(source, content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'));

    protected static IReadOnlyList<ProxyCandidate> ParseLines(ProxySourceDefinition source, IEnumerable<string> lines)
    {
        var results = new List<ProxyCandidate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (line.Length > 65_536) continue;
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var matches = UriPattern.Matches(line);
            if (matches.Count > 0)
            {
                foreach (Match match in matches) Add(match, source, rawLine, results, seen, true);
                continue;
            }
            matches = HostPortPattern.Matches(line);
            if (matches.Count > 0)
            {
                foreach (Match match in matches) Add(match, source, rawLine, results, seen, false);
                continue;
            }
            var columns = ColumnsPattern.Match(line);
            if (columns.Success) Add(columns, source, rawLine, results, seen, false);
        }
        return results;
    }

    private static void Add(Match match, ProxySourceDefinition source, string raw, List<ProxyCandidate> results,
        HashSet<string> seen, bool includesCredentials)
    {
        if (!int.TryParse(match.Groups["port"].Value, out var port)) return;
        var host = match.Groups["host"].Value.Trim('[', ']');
        var protocolText = match.Groups["scheme"].Success ? match.Groups["scheme"].Value
            : match.Groups["protocol"].Success ? match.Groups["protocol"].Value : string.Empty;
        var protocol = ParseProtocol(protocolText, source.DeclaredProtocol);
        var username = includesCredentials && match.Groups["user"].Success ? match.Groups["user"].Value : null;
        var password = includesCredentials && match.Groups["pass"].Success ? match.Groups["pass"].Value : null;
        var key = $"{protocol}|{host}|{port}|{username}";
        if (seen.Add(key)) results.Add(new ProxyCandidate(host, port, protocol, source.Name, DateTimeOffset.UtcNow, username, password, raw));
    }

    public static ProxyProtocol ParseProtocol(string value, ProxyProtocol fallback) => value.ToLowerInvariant() switch
    {
        "http" => ProxyProtocol.Http,
        "https" => ProxyProtocol.HttpsConnect,
        "socks4" => ProxyProtocol.Socks4,
        "socks4a" => ProxyProtocol.Socks4a,
        "socks5" => ProxyProtocol.Socks5,
        _ => fallback
    };
}

public sealed class TextProxyParser : LineProxyParser
{
    public override bool CanParse(string format) => format.Equals("text", StringComparison.OrdinalIgnoreCase)
        || format.Equals("github-raw", StringComparison.OrdinalIgnoreCase)
        || format.Equals("local-file", StringComparison.OrdinalIgnoreCase);
}

public sealed class CsvProxyParser : LineProxyParser
{
    public override bool CanParse(string format) => format.Equals("csv", StringComparison.OrdinalIgnoreCase);
}

public sealed class HtmlProxyParser : LineProxyParser
{
    public override bool CanParse(string format) => format.Equals("html", StringComparison.OrdinalIgnoreCase);
    public override IReadOnlyList<ProxyCandidate> Parse(ProxySourceDefinition source, string content)
    {
        var document = new HtmlParser().ParseDocument(content);
        return ParseLines(source, document.Body?.TextContent.Split('\n') ?? [document.DocumentElement.TextContent]);
    }
}

public sealed class JsonProxyParser : IProxyParser
{
    private static readonly string[] HostNames = ["ip", "host", "address"];
    private static readonly string[] ProtocolNames = ["protocol", "type"];
    public bool CanParse(string format) => format.Equals("json", StringComparison.OrdinalIgnoreCase);

    public IReadOnlyList<ProxyCandidate> Parse(ProxySourceDefinition source, string content)
    {
        using var document = JsonDocument.Parse(content, new JsonDocumentOptions
        {
            MaxDepth = 64,
            AllowTrailingCommas = true,
            CommentHandling = JsonCommentHandling.Skip
        });
        var root = SelectConfiguredPath(document.RootElement, source);
        var results = new List<ProxyCandidate>();
        Visit(root, source, results);
        return results;
    }

    private static JsonElement SelectConfiguredPath(JsonElement root, ProxySourceDefinition source)
    {
        if (!source.ParserOptions.TryGetValue("path", out var option) || option.ValueKind != JsonValueKind.String) return root;
        var current = root;
        foreach (var part in (option.GetString() ?? string.Empty).Trim('$', '.').Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            if (current.ValueKind == JsonValueKind.Object && TryProperty(current, [part], out var next)) current = next;
            else return root;
        }
        return current;
    }

    private static void Visit(JsonElement element, ProxySourceDefinition source, List<ProxyCandidate> results)
    {
        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var child in element.EnumerateArray()) Visit(child, source, results);
            return;
        }
        if (element.ValueKind != JsonValueKind.Object) return;
        if (TryProperty(element, HostNames, out var hostNode) && TryProperty(element, ["port"], out var portNode)
            && TryInt32(portNode, out var port))
        {
            var host = hostNode.ToString();
            TryProperty(element, ProtocolNames, out var protocolNode);
            TryProperty(element, ["username"], out var userNode);
            TryProperty(element, ["password"], out var passwordNode);
            results.Add(new ProxyCandidate(host, port, LineProxyParser.ParseProtocol(protocolNode.ToString(), source.DeclaredProtocol),
                source.Name, DateTimeOffset.UtcNow, NullIfUndefined(userNode), NullIfUndefined(passwordNode), element.GetRawText()));
        }
        else
        {
            foreach (var property in element.EnumerateObject()) Visit(property.Value, source, results);
        }
    }

    private static bool TryProperty(JsonElement element, IEnumerable<string> names, out JsonElement value)
    {
        foreach (var property in element.EnumerateObject())
            if (names.Any(name => property.Name.Equals(name, StringComparison.OrdinalIgnoreCase))) { value = property.Value; return true; }
        value = default; return false;
    }

    private static bool TryInt32(JsonElement value, out int result) => value.ValueKind == JsonValueKind.Number
        ? value.TryGetInt32(out result) : int.TryParse(value.ToString(), out result);
    private static string? NullIfUndefined(JsonElement value) => value.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null ? null : value.ToString();
}
