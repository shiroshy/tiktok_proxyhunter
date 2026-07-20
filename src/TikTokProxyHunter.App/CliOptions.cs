namespace TikTokProxyHunter.App;

public sealed record CliOptions
{
    public string Command { get; init; } = "all";
    public string SourcesPath { get; init; } = "config/proxy-sources.json";
    public string? InputPath { get; init; }
    public string? OutputPath { get; init; }
    public string? Protocol { get; init; }
    public int MinScore { get; init; }
    public int? Concurrency { get; init; }
    public int? TimeoutSeconds { get; init; }
    public int? Limit { get; init; }
    public string GitHubTokenEnvironment { get; init; } = "TIKTOK_PROXY_HUNTER_GITHUB_TOKEN";
    public IReadOnlyList<string> IncludeSources { get; init; } = [];
    public IReadOnlyList<string> ExcludeSources { get; init; } = [];
    public int? MaximumCandidates { get; init; }
    public IReadOnlyList<string> RejectCountries { get; init; } = [];
    public IReadOnlyList<string> PreferredCountries { get; init; } = [];
    public IReadOnlyList<string> TikTokVideoUrls { get; init; } = [];
    public bool BrowserCheck { get; init; }
    public int? BrowserLimit { get; init; }
    public int? StabilityAttempts { get; init; }
    public bool Resume { get; init; }
    public bool Apply { get; init; }
    public bool? AllowUnknownGeo { get; init; }
    public bool? AllowConflictingGeo { get; init; }
    public bool? RejectLikelyRu { get; init; }
    public string? MinimumGeoConfidence { get; init; }
    public string? GeoCountryDatabasePath { get; init; }
    public string? GeoAsnDatabasePath { get; init; }
    public string? TikTokVideoFile { get; init; }
    public string? ProxySelector { get; init; }
    public bool OnlyTikTokAccessible { get; init; }
    public bool ShowHelp { get; init; }

    public static CliOptions Parse(string[] args)
    {
        var command = args.FirstOrDefault(x => !x.StartsWith('-')) ?? "all";
        if (command is not ("collect" or "probe" or "check-tiktok" or "all" or "refresh-sources"
            or "discover-sources" or "import-discovered-sources" or "resolve-exit" or "resolve-geo"
            or "verify-tiktok" or "verify-browser" or "all-real" or "validate-geo-database"
            or "browser-doctor" or "verify-browser-live" or "export-user-list" or "explain-proxy"
            or "test-exit-providers" or "retry-exit-resolution" or "validate-tiktok-videos" or "continue-verification"))
            throw new ArgumentException($"Unknown command '{command}'.");
        string? Value(string name)
        {
            var index = Array.FindIndex(args, x => x.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (index < 0) return null;
            if (index + 1 >= args.Length || args[index + 1].StartsWith('-')) throw new ArgumentException($"Missing value for {name}");
            return args[index + 1];
        }
        int? IntValue(string name) => Value(name) is { } value && int.TryParse(value, out var number)
            ? number : Value(name) is null ? null : throw new ArgumentException($"Invalid integer for {name}");
        IReadOnlyList<string> Values(string name)
        {
            var values = new List<string>();
            for (var index = 0; index < args.Length; index++)
                if (args[index].Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    if (index + 1 >= args.Length || args[index + 1].StartsWith('-')) throw new ArgumentException($"Missing value for {name}");
                    values.AddRange(args[index + 1].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                }
            return values;
        }
        return new CliOptions
        {
            Command = command, SourcesPath = Value("--sources") ?? "config/proxy-sources.json",
            InputPath = Value("--input"), OutputPath = Value("--output"), Protocol = Value("--protocol"),
            MinScore = IntValue("--min-score") ?? 0, Concurrency = IntValue("--concurrency"),
            TimeoutSeconds = IntValue("--timeout"), Limit = IntValue("--limit"),
            GitHubTokenEnvironment = Value("--github-token-env") ?? "TIKTOK_PROXY_HUNTER_GITHUB_TOKEN",
            IncludeSources = Values("--include-source"), ExcludeSources = Values("--exclude-source"),
            MaximumCandidates = IntValue("--max-candidates"), RejectCountries = Values("--reject-country"),
            PreferredCountries = Values("--preferred-country"), TikTokVideoUrls = Values("--tiktok-video-url"),
            BrowserCheck = args.Contains("--browser-check", StringComparer.OrdinalIgnoreCase),
            BrowserLimit = IntValue("--browser-limit"), StabilityAttempts = IntValue("--stability-attempts"),
            Resume = args.Contains("--resume", StringComparer.OrdinalIgnoreCase),
            Apply = args.Contains("--apply", StringComparer.OrdinalIgnoreCase),
            AllowUnknownGeo = BoolSwitch("--allow-unknown-geo", "--deny-unknown-geo"),
            AllowConflictingGeo = BoolSwitch("--allow-conflicting-geo", "--deny-conflicting-geo"),
            RejectLikelyRu = BoolSwitch("--reject-likely-ru", "--allow-likely-ru"),
            MinimumGeoConfidence = Value("--minimum-geo-confidence"),
            GeoCountryDatabasePath = Value("--geo-country-db"), GeoAsnDatabasePath = Value("--geo-asn-db"),
            TikTokVideoFile = Value("--tiktok-video-file"), ProxySelector = Value("--proxy"),
            OnlyTikTokAccessible = args.Contains("--only-tiktok-accessible", StringComparer.OrdinalIgnoreCase),
            ShowHelp = args.Any(x => x is "--help" or "-h")
        };

        bool? BoolSwitch(string enabled, string disabled) => args.Contains(enabled, StringComparer.OrdinalIgnoreCase) ? true
            : args.Contains(disabled, StringComparer.OrdinalIgnoreCase) ? false : null;
    }

    public static void PrintHelp() => Console.WriteLine("""
TikTokProxyHunter commands:
  dotnet run --project src/TikTokProxyHunter.App -- collect [options]
  dotnet run --project src/TikTokProxyHunter.App -- probe --input <normalized.jsonl> [options]
  dotnet run --project src/TikTokProxyHunter.App -- check-tiktok --input <working-proxies.json> [options]
  dotnet run --project src/TikTokProxyHunter.App -- all [options]
  dotnet run --project src/TikTokProxyHunter.App -- refresh-sources
  dotnet run --project src/TikTokProxyHunter.App -- discover-sources
  dotnet run --project src/TikTokProxyHunter.App -- import-discovered-sources [--apply]
  dotnet run --project src/TikTokProxyHunter.App -- resolve-exit --input <file>
  dotnet run --project src/TikTokProxyHunter.App -- resolve-geo --input <file>
  dotnet run --project src/TikTokProxyHunter.App -- verify-tiktok --input <file>
  dotnet run --project src/TikTokProxyHunter.App -- verify-browser --input <file> --tiktok-video-url <url>
  dotnet run --project src/TikTokProxyHunter.App -- all-real [options]
  dotnet run --project src/TikTokProxyHunter.App -- validate-geo-database
  dotnet run --project src/TikTokProxyHunter.App -- browser-doctor
  dotnet run --project src/TikTokProxyHunter.App -- verify-browser-live --input <best-proxies.json> --tiktok-video-file <file>
  dotnet run --project src/TikTokProxyHunter.App -- export-user-list --input <best-proxies.json> --output <directory>
  dotnet run --project src/TikTokProxyHunter.App -- explain-proxy --input <best-proxies.json> --proxy <IP:PORT>
  dotnet run --project src/TikTokProxyHunter.App -- test-exit-providers
  dotnet run --project src/TikTokProxyHunter.App -- retry-exit-resolution --input <best-proxies.json> [--only-tiktok-accessible]
  dotnet run --project src/TikTokProxyHunter.App -- validate-tiktok-videos --input config/tiktok-test-videos.local.json
  dotnet run --project src/TikTokProxyHunter.App -- continue-verification --input <best-proxies.json> --tiktok-video-file <file>

Options: --sources --input --output --protocol --min-score --concurrency --timeout --limit
         --github-token-env --include-source --exclude-source --max-candidates
         --reject-country --preferred-country --tiktok-video-url --browser-check
         --browser-limit --stability-attempts --resume --apply
         --allow-unknown-geo --allow-conflicting-geo --reject-likely-ru
         --minimum-geo-confidence --geo-country-db --geo-asn-db --tiktok-video-file --proxy
         --only-tiktok-accessible
""");

    public bool IsStage2Command => Command is "refresh-sources" or "discover-sources" or "import-discovered-sources"
        or "resolve-exit" or "resolve-geo" or "verify-tiktok" or "verify-browser" or "all-real"
        or "validate-geo-database" or "browser-doctor" or "verify-browser-live" or "export-user-list" or "explain-proxy"
        or "test-exit-providers" or "retry-exit-resolution" or "validate-tiktok-videos" or "continue-verification";
}
