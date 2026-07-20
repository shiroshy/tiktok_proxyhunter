using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Infrastructure;

namespace TikTokProxyHunter.App;

public sealed class PipelineRunner(
    IProxySourceLoader sourceLoader,
    IEnumerable<IProxyParser> parsers,
    IProxyNormalizer normalizer,
    IProxyDeduplicator deduplicator,
    IProxyProtocolDetector detector,
    ITikTokChecker tikTokChecker,
    IProxyScorer scorer,
    IResultExporter exporter,
    HunterOptions options,
    ILogger<PipelineRunner> logger)
{
    public async Task<int> RunAsync(CliOptions cli, CancellationToken cancellationToken)
    {
        var started = Stopwatch.StartNew();
        var output = cli.OutputPath ?? Path.Combine("output", DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmss.fffZ"));
        Directory.CreateDirectory(output);
        var candidates = new List<ProxyCandidate>();
        IReadOnlyList<ProxyEndpoint> unique;
        IReadOnlyList<ProxySourceDefinition> definitions = [];
        IReadOnlyList<ProxySourceResult> sourceResults = [];

        if (cli.Command is "collect" or "all")
        {
            definitions = await sourceLoader.LoadDefinitionsAsync(cli.SourcesPath, cancellationToken);
            sourceResults = await sourceLoader.LoadEnabledAsync(definitions, cancellationToken);
            var definitionsByName = definitions.ToDictionary(x => x.Name, StringComparer.OrdinalIgnoreCase);
            foreach (var result in sourceResults.Where(x => x.Success && x.Content is not null))
            {
                var definition = definitionsByName[result.SourceName];
                var parser = parsers.FirstOrDefault(x => x.CanParse(definition.Format == "local-file" ? InferLocalFormat(definition) : definition.Format));
                if (parser is null) { logger.LogWarning("No parser for source {Source}", definition.Name); continue; }
                var effective = definition.Format == "local-file" ? definition with { Format = InferLocalFormat(definition) } : definition;
                try { candidates.AddRange(parser.Parse(effective, result.Content!)); }
                catch (Exception ex) when (ex is JsonException or FormatException) { logger.LogWarning("Could not parse {Source}: {Reason}", definition.Name, ex.Message); }
            }
            var normalized = new List<ProxyEndpoint>();
            foreach (var candidate in candidates)
                if (normalizer.TryNormalize(candidate, out var endpoint, out _)) normalized.Add(endpoint!);
            unique = deduplicator.Deduplicate(normalized);
            Console.WriteLine($"Sources: {sourceResults.Count(x => x.Success)}/{definitions.Count(x => x.Enabled)}");
            Console.WriteLine($"Candidates: {candidates.Count:N0}");
            Console.WriteLine($"Unique: {unique.Count:N0}");
            if (cli.Command == "collect")
            {
                var summary = BuildSummary(definitions, sourceResults, candidates.Count, normalized.Count, unique, [], started.Elapsed);
                await exporter.ExportAsync(output, candidates, unique, [], summary, cancellationToken);
                Console.WriteLine($"Output: {Path.GetFullPath(output)}");
                return 0;
            }
        }
        else
        {
            if (string.IsNullOrWhiteSpace(cli.InputPath)) throw new ArgumentException($"Command '{cli.Command}' requires --input.");
            unique = await ReadEndpointsAsync(cli.InputPath, cancellationToken);
        }

        unique = ApplyFilters(unique, cli).ToArray();
        var checks = cli.Command == "check-tiktok"
            ? unique.Select(x => new ProxyCheckResult { Endpoint = x, Probe = new ProxyProbeResult { Endpoint = x, Success = x.DetectedProtocol != ProxyProtocol.Unknown, Protocol = x.DetectedProtocol } }).ToArray()
            : await ProbeAsync(unique, cancellationToken);
        Console.WriteLine($"Probed: {checks.Count(x => x.Probe?.Success == true):N0}/{unique.Count:N0}");

        if (cli.Command is "all" or "check-tiktok")
        {
            checks = await CheckTikTokAsync(checks, cancellationToken);
            Console.WriteLine($"TikTok accessible: {checks.Count(x => x.TikTokChecks.Any(t => t.Status == TikTokStatus.Accessible)):N0}");
        }
        checks = checks.Select(x => x with { Score = scorer.Calculate(x) }).Where(x => x.Score.Value >= cli.MinScore).ToArray();
        var finalSummary = BuildSummary(definitions, sourceResults, candidates.Count, unique.Count, unique, checks, started.Elapsed);
        await exporter.ExportAsync(output, candidates, unique, checks, finalSummary, cancellationToken);
        Console.WriteLine($"Output: {Path.GetFullPath(output)}");
        return 0;
    }

    private async Task<ProxyCheckResult[]> ProbeAsync(IReadOnlyList<ProxyEndpoint> endpoints, CancellationToken token)
    {
        var results = new ConcurrentBag<ProxyCheckResult>();
        var completed = 0;
        await Parallel.ForEachAsync(endpoints, new ParallelOptions { MaxDegreeOfParallelism = options.ProbeConcurrency, CancellationToken = token }, async (endpoint, ct) =>
        {
            var probe = await detector.DetectAsync(endpoint, ct);
            var detected = endpoint with { DetectedProtocol = probe.Success ? probe.Protocol : ProxyProtocol.Unknown };
            results.Add(new ProxyCheckResult { Endpoint = detected, Probe = probe with { Endpoint = detected } });
            var count = Interlocked.Increment(ref completed);
            if (count % 250 == 0 || count == endpoints.Count) Console.WriteLine($"Probed: {count:N0}/{endpoints.Count:N0}");
        });
        return results.OrderBy(x => x.Endpoint.NormalizedKey, StringComparer.Ordinal).ToArray();
    }

    private async Task<ProxyCheckResult[]> CheckTikTokAsync(IReadOnlyList<ProxyCheckResult> checks, CancellationToken token)
    {
        var working = checks.Where(x => x.Probe?.Success == true && x.Endpoint.DetectedProtocol != ProxyProtocol.Http).ToArray();
        var results = new ConcurrentBag<ProxyCheckResult>();
        await Parallel.ForEachAsync(working, new ParallelOptions { MaxDegreeOfParallelism = options.ProbeConcurrency, CancellationToken = token }, async (check, ct) =>
        {
            var tikTokChecks = new List<TikTokCheckResult>();
            foreach (var value in options.TikTokUrls.Distinct(StringComparer.OrdinalIgnoreCase))
                if (Uri.TryCreate(value, UriKind.Absolute, out var uri)) tikTokChecks.Add(await tikTokChecker.CheckAsync(check.Endpoint, uri, ct));
            results.Add(check with { TikTokChecks = tikTokChecks, SuccessfulChecks = tikTokChecks.Count(x => x.Status == TikTokStatus.Accessible) });
        });
        foreach (var skipped in checks.Except(working)) results.Add(skipped);
        return results.OrderBy(x => x.Endpoint.NormalizedKey, StringComparer.Ordinal).ToArray();
    }

    private static IEnumerable<ProxyEndpoint> ApplyFilters(IEnumerable<ProxyEndpoint> endpoints, CliOptions cli)
    {
        var result = endpoints;
        if (!string.IsNullOrWhiteSpace(cli.Protocol) && Enum.TryParse<ProxyProtocol>(cli.Protocol, true, out var protocol))
            result = result.Where(x => x.DeclaredProtocol == protocol || x.DetectedProtocol == protocol);
        if (cli.Limit is > 0) result = result.Take(cli.Limit.Value);
        return result;
    }

    private static string InferLocalFormat(ProxySourceDefinition definition) =>
        Path.GetExtension(definition.Path ?? string.Empty).ToLowerInvariant() switch { ".csv" => "csv", ".json" => "json", ".html" or ".htm" => "html", _ => "text" };

    private static async Task<IReadOnlyList<ProxyEndpoint>> ReadEndpointsAsync(string path, CancellationToken token)
    {
        if (Path.GetExtension(path).Equals(".jsonl", StringComparison.OrdinalIgnoreCase))
        {
            var lines = await File.ReadAllLinesAsync(path, token);
            return lines.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => JsonSerializer.Deserialize<ProxyEndpoint>(x, JsonDefaults.Options)!).Where(x => x is not null).ToArray();
        }
        var json = await File.ReadAllTextAsync(path, token);
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind == JsonValueKind.Array && document.RootElement.GetArrayLength() > 0
            && document.RootElement[0].ValueKind == JsonValueKind.Object
            && document.RootElement[0].TryGetProperty("endpoint", out _))
            return JsonSerializer.Deserialize<List<ProxyCheckResult>>(json, JsonDefaults.Options)?.Select(x => x.Endpoint).ToArray() ?? [];
        return JsonSerializer.Deserialize<List<ProxyEndpoint>>(json, JsonDefaults.Options) ?? [];
    }

    private static RunSummary BuildSummary(IReadOnlyList<ProxySourceDefinition> definitions, IReadOnlyList<ProxySourceResult> sourceResults,
        int found, int valid, IReadOnlyList<ProxyEndpoint> unique, IReadOnlyList<ProxyCheckResult> checks, TimeSpan duration)
    {
        var latencies = checks.SelectMany(x => x.TikTokChecks).Where(x => x.TotalTime > TimeSpan.Zero).Select(x => x.TotalTime.TotalMilliseconds).Order().ToArray();
        return new RunSummary
        {
            Sources = definitions.Count(x => x.Enabled), SuccessfulSources = sourceResults.Count(x => x.Success), SourceErrors = sourceResults.Count(x => !x.Success),
            FoundRows = found, ValidCandidates = valid, UniqueEndpoints = unique.Count,
            Protocols = unique.GroupBy(x => x.DetectedProtocol).ToDictionary(x => x.Key.ToString(), x => x.Count()),
            TikTokAccessible = checks.Count(x => x.TikTokChecks.Any(t => t.Status == TikTokStatus.Accessible)),
            CaptchaOrChallenge = checks.SelectMany(x => x.TikTokChecks).Count(x => x.Status == TikTokStatus.CaptchaOrChallenge),
            Timeouts = checks.SelectMany(x => x.TikTokChecks).Count(x => x.Status == TikTokStatus.Timeout),
            AverageLatencyMs = latencies.Length == 0 ? 0 : latencies.Average(),
            MedianLatencyMs = latencies.Length == 0 ? 0 : (latencies[(latencies.Length - 1) / 2] + latencies[latencies.Length / 2]) / 2,
            Duration = duration
        };
    }
}
