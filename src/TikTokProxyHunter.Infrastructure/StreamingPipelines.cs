using System.Collections.Concurrent;
using System.Threading.Channels;
using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Infrastructure;

public sealed record StreamingCollectionResult(IReadOnlyList<ProxyEndpoint> Endpoints, long Candidates,
    long ValidCandidates, long DroppedByMemoryLimit, IReadOnlyDictionary<string, (int Extracted, int Valid)> SourceCounts);

public sealed class StreamingCandidateProcessor(
    IEnumerable<IProxyParser> parsers,
    IProxyNormalizer normalizer,
    HunterOptions options)
{
    public async Task<StreamingCollectionResult> ProcessAsync(
        IEnumerable<(ProxySourceDefinition Definition, ProxySourceResult Result)> sources,
        CancellationToken cancellationToken)
    {
        var channel = Channel.CreateBounded<ProxyCandidate>(new BoundedChannelOptions(Math.Max(1, options.ChannelCapacity))
        { SingleReader = true, FullMode = BoundedChannelFullMode.Wait });
        var counts = new ConcurrentDictionary<string, MutableCounts>(StringComparer.OrdinalIgnoreCase);
        long total = 0; long valid = 0; long dropped = 0;
        var dictionary = new Dictionary<string, ProxyEndpoint>(StringComparer.OrdinalIgnoreCase);
        var sourceFamilies = sources.ToDictionary(x => x.Definition.Name,
            x => x.Definition.SourceFamily ?? x.Definition.Name, StringComparer.OrdinalIgnoreCase);
        var consumer = Task.Run(async () =>
        {
            await foreach (var candidate in channel.Reader.ReadAllAsync(cancellationToken))
            {
                if (!normalizer.TryNormalize(candidate, out var endpoint, out _)) continue;
                Interlocked.Increment(ref valid); counts.GetOrAdd(candidate.Source, _ => new()).IncrementValid();
                endpoint = endpoint! with { SourceFamilies = [sourceFamilies.GetValueOrDefault(candidate.Source, candidate.Source)] };
                var key = $"{endpoint.Host}|{endpoint.Port}|{endpoint.DeclaredProtocol}|{endpoint.Username}";
                if (dictionary.TryGetValue(key, out var existing))
                {
                    var allSources = existing.Sources.Append(candidate.Source).Distinct(StringComparer.OrdinalIgnoreCase).Order().ToArray();
                    var allFamilies = existing.SourceFamilies.Append(sourceFamilies.GetValueOrDefault(candidate.Source, candidate.Source))
                        .Distinct(StringComparer.OrdinalIgnoreCase).Order().ToArray();
                    dictionary[key] = existing with { Sources = allSources, SourceFamilies = allFamilies, ObservationCount = existing.ObservationCount + 1 };
                }
                else if (dictionary.Count < options.DeduplicationMemoryLimit) dictionary[key] = endpoint;
                else Interlocked.Increment(ref dropped);
            }
        }, cancellationToken);

        await Parallel.ForEachAsync(sources.Where(x => x.Result.Success && x.Result.Content is not null),
            new ParallelOptions { MaxDegreeOfParallelism = options.CollectionConcurrency, CancellationToken = cancellationToken },
            async (source, ct) =>
            {
                var format = source.Definition.Format == "local-file" ? InferFormat(source.Definition.Path) : source.Definition.Format;
                var parser = parsers.FirstOrDefault(x => x.CanParse(format)); if (parser is null) return;
                var definition = source.Definition with { Format = format };
                if (format is "text" or "csv" or "github-raw")
                {
                    using var reader = new StringReader(source.Result.Content!); string? line;
                    while ((line = await reader.ReadLineAsync(ct)) is not null)
                    {
                        if (line.Length > options.MaximumLineLength) continue;
                        foreach (var candidate in parser.Parse(definition, line))
                        {
                            var current = Interlocked.Increment(ref total);
                            if (options.MaximumCandidates > 0 && current > options.MaximumCandidates) return;
                            counts.GetOrAdd(definition.Name, _ => new()).IncrementExtracted();
                            await channel.Writer.WriteAsync(candidate, ct);
                        }
                    }
                }
                else
                {
                    foreach (var candidate in parser.Parse(definition, source.Result.Content!))
                    {
                        var current = Interlocked.Increment(ref total);
                        if (options.MaximumCandidates > 0 && current > options.MaximumCandidates) return;
                        counts.GetOrAdd(definition.Name, _ => new()).IncrementExtracted();
                        await channel.Writer.WriteAsync(candidate, ct);
                    }
                }
            });
        channel.Writer.Complete();
        await consumer;
        return new StreamingCollectionResult(dictionary.Values.OrderBy(x => x.NormalizedKey).ToArray(),
            Math.Min(total, options.MaximumCandidates > 0 ? options.MaximumCandidates : total), valid, dropped,
            counts.ToDictionary(x => x.Key, x => (x.Value.Extracted, x.Value.Valid), StringComparer.OrdinalIgnoreCase));
    }

    private static string InferFormat(string? path) => Path.GetExtension(path ?? string.Empty).ToLowerInvariant() switch
    { ".csv" => "csv", ".json" => "json", ".html" or ".htm" => "html", _ => "text" };
    private sealed class MutableCounts
    { private int _extracted; private int _valid; public int Extracted => _extracted; public int Valid => _valid;
      public void IncrementExtracted() => Interlocked.Increment(ref _extracted); public void IncrementValid() => Interlocked.Increment(ref _valid); }
}

public sealed class StreamingProbePipeline(IProxyProtocolDetector detector, HunterOptions options)
{
    public async Task<IReadOnlyList<ProxyCheckResult>> ProbeAsync(IEnumerable<ProxyEndpoint> endpoints,
        IReadOnlySet<string>? completed, CancellationToken cancellationToken)
    {
        var channel = Channel.CreateBounded<ProxyEndpoint>(new BoundedChannelOptions(Math.Max(1, options.ChannelCapacity))
        { SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
        var results = new ConcurrentBag<ProxyCheckResult>();
        var workers = Enumerable.Range(0, Math.Max(1, options.ProbeConcurrency)).Select(_ => Task.Run(async () =>
        {
            await foreach (var endpoint in channel.Reader.ReadAllAsync(cancellationToken))
            {
                var probe = await detector.DetectAsync(endpoint, cancellationToken);
                var detected = endpoint with { DetectedProtocol = probe.Success ? probe.Protocol : ProxyProtocol.Unknown };
                results.Add(new ProxyCheckResult { Endpoint = detected, Probe = probe with { Endpoint = detected } });
            }
        }, cancellationToken)).ToArray();
        foreach (var endpoint in endpoints)
            if (completed?.Contains(endpoint.NormalizedKey) != true) await channel.Writer.WriteAsync(endpoint, cancellationToken);
        channel.Writer.Complete(); await Task.WhenAll(workers);
        return results.OrderBy(x => x.Endpoint.NormalizedKey).ToArray();
    }
}
