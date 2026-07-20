using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text.Json;
using System.Text;
using Microsoft.Extensions.Logging;
using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Infrastructure;

public sealed class ProxySourceLoader(
    IEnumerable<IProxySource> sources,
    HunterOptions options,
    ILogger<ProxySourceLoader> logger) : IProxySourceLoader
{
    private readonly SemaphoreSlim _global = new(Math.Max(1, options.CollectionConcurrency));
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _perHost = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, int> _consecutiveFailures = new(StringComparer.OrdinalIgnoreCase);

    public async Task<IReadOnlyList<ProxySourceDefinition>> LoadDefinitionsAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = File.OpenRead(path);
        return await JsonSerializer.DeserializeAsync<List<ProxySourceDefinition>>(stream, JsonDefaults.Options, cancellationToken)
            ?? [];
    }

    public async Task<IReadOnlyList<ProxySourceResult>> LoadEnabledAsync(
        IEnumerable<ProxySourceDefinition> definitions, CancellationToken cancellationToken)
    {
        var enabled = definitions.Where(x => x.Enabled).ToArray();
        var tasks = enabled.Select(definition => LoadOneAsync(definition, cancellationToken));
        return await Task.WhenAll(tasks);
    }

    private async Task<ProxySourceResult> LoadOneAsync(ProxySourceDefinition definition, CancellationToken cancellationToken)
    {
        if (_consecutiveFailures.GetValueOrDefault(definition.Name) >= 3)
            return new ProxySourceResult { SourceName = definition.Name,
                Error = "Temporarily disabled after three consecutive failures in this process" };
        var adapter = sources.FirstOrDefault(x => x.CanHandle(definition));
        if (adapter is null)
            return new ProxySourceResult { SourceName = definition.Name, Error = $"Unsupported format '{definition.Format}'" };

        var hostKey = Uri.TryCreate(definition.Url, UriKind.Absolute, out var uri) ? uri.Host : "local-file";
        var hostSemaphore = _perHost.GetOrAdd(hostKey, _ => new SemaphoreSlim(Math.Max(1, options.PerSourceHostConcurrency)));
        await _global.WaitAsync(cancellationToken);
        await hostSemaphore.WaitAsync(cancellationToken);
        try
        {
            var result = await adapter.LoadAsync(definition, cancellationToken);
            if (result.Success) _consecutiveFailures.TryRemove(definition.Name, out _);
            else _consecutiveFailures.AddOrUpdate(definition.Name, 1, (_, value) => value + 1);
            return result;
        }
        catch (Exception ex) when (ex is IOException or HttpRequestException or UnauthorizedAccessException or JsonException)
        {
            logger.LogWarning("Source {Source} skipped: {Reason}", definition.Name, ex.Message);
            _consecutiveFailures.AddOrUpdate(definition.Name, 1, (_, value) => value + 1);
            return new ProxySourceResult { SourceName = definition.Name, Error = ex.Message, Attempts = 1 };
        }
        finally
        {
            hostSemaphore.Release();
            _global.Release();
        }
    }
}

public abstract class RemoteProxySource(
    IHttpClientFactory clientFactory,
    HunterOptions options,
    SourcePayloadCache cache,
    ISourceContentFingerprintService fingerprints,
    ILogger logger) : IProxySource
{
    protected abstract IReadOnlySet<string> Formats { get; }
    public bool CanHandle(ProxySourceDefinition definition) => !string.IsNullOrWhiteSpace(definition.Url) && Formats.Contains(definition.Format);

    public async Task<ProxySourceResult> LoadAsync(ProxySourceDefinition definition, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(definition.Url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
            return Failure(definition, "A public HTTP(S) URL is required", 0, TimeSpan.Zero);

        var stopwatch = Stopwatch.StartNew();
        var cached = await cache.GetAsync(uri, cancellationToken);
        var attempts = 0;
        Exception? lastError = null;
        var maxAttempts = Math.Max(1, options.Retries + 1);
        while (attempts < maxAttempts)
        {
            attempts++;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(definition.TimeoutSeconds > 0 ? definition.TimeoutSeconds : options.SourceTimeoutSeconds));
            try
            {
                var client = clientFactory.CreateClient("proxy-sources");
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                if (!string.IsNullOrWhiteSpace(cached?.ETag)) request.Headers.TryAddWithoutValidation("If-None-Match", cached.ETag);
                if (cached?.LastModified is { } modified) request.Headers.IfModifiedSince = modified;
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
                var mediaType = response.Content.Headers.ContentType?.MediaType;
                var etag = response.Headers.ETag?.ToString();
                var lastModified = response.Content.Headers.LastModified ?? response.Headers.Date;
                if (response.StatusCode == HttpStatusCode.NotModified)
                {
                    if (cached is null) return Failure(definition, "304 received without cached payload", attempts, stopwatch.Elapsed, 304, mediaType);
                    var cachedText = DecodeText(cached.Payload);
                    return Success(definition, cachedText, cached.Payload, attempts, stopwatch.Elapsed, 304,
                        mediaType ?? definition.ExpectedContentType, cached.ETag, cached.LastModified, true, fingerprints);
                }
                if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                    return Failure(definition, $"Source requires authorization or blocks automation ({(int)response.StatusCode})", attempts, stopwatch.Elapsed, (int)response.StatusCode, mediaType);
                if ((int)response.StatusCode == 429)
                    return Failure(definition, "Rate limited (429)", attempts, stopwatch.Elapsed, 429, mediaType);
                else
                {
                    response.EnsureSuccessStatusCode();
                    if (mediaType?.Contains("html", StringComparison.OrdinalIgnoreCase) == true
                        && response.Headers.Contains("cf-mitigated"))
                        return Failure(definition, "Cloudflare challenge detected; source skipped", attempts, stopwatch.Elapsed, (int)response.StatusCode, mediaType);
                    var limit = Math.Min(options.MaximumSourcePayloadBytes, definition.MaximumDownloadBytes > 0
                        ? definition.MaximumDownloadBytes : options.MaximumSourcePayloadBytes);
                    if (response.Content.Headers.ContentLength is > 0 && response.Content.Headers.ContentLength > limit)
                        return Failure(definition, $"Oversized payload: declared {response.Content.Headers.ContentLength} bytes, maximum {limit}", attempts, stopwatch.Elapsed, (int)response.StatusCode, mediaType);
                    await using var responseStream = await response.Content.ReadAsStreamAsync(timeout.Token);
                    var payload = await ReadLimitedAsync(responseStream, limit, timeout.Token);
                    if (LooksBinary(payload))
                        return Failure(definition, "Suspicious binary content", attempts, stopwatch.Elapsed, (int)response.StatusCode, mediaType, payload.LongLength);
                    var content = DecodeText(payload);
                    if (LooksLikeChallenge(content))
                        return Failure(definition, "CAPTCHA or anti-bot challenge detected; source skipped", attempts, stopwatch.Elapsed, (int)response.StatusCode, mediaType, payload.LongLength);
                    await cache.SaveAsync(uri, etag, lastModified, payload, timeout.Token);
                    return Success(definition, content, payload, attempts, stopwatch.Elapsed, (int)response.StatusCode,
                        mediaType, etag, lastModified, false, fingerprints);
                }
            }
            catch (Exception ex) when (IsTransient(ex, cancellationToken))
            {
                lastError = ex;
                logger.LogDebug(ex, "Transient failure loading {Source}, attempt {Attempt}", definition.Name, attempts);
            }

            if (attempts < maxAttempts)
            {
                var jitter = Random.Shared.Next(25, 150);
                await Task.Delay(TimeSpan.FromMilliseconds((200 * Math.Pow(2, attempts - 1)) + jitter), cancellationToken);
            }
        }
        return Failure(definition, lastError?.Message ?? "Unknown source error", attempts, stopwatch.Elapsed);
    }

    private static bool IsTransient(Exception ex, CancellationToken callerToken) =>
        ex is HttpRequestException || ex is IOException || (ex is OperationCanceledException && !callerToken.IsCancellationRequested);

    private static bool LooksLikeChallenge(string content)
    {
        var sample = content.AsSpan(0, Math.Min(content.Length, 16_384));
        return sample.Contains("captcha", StringComparison.OrdinalIgnoreCase)
            || sample.Contains("cf-chl-", StringComparison.OrdinalIgnoreCase)
            || sample.Contains("challenge-platform", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<byte[]> ReadLimitedAsync(Stream stream, long limit, CancellationToken token)
    {
        await using var buffer = new MemoryStream((int)Math.Min(limit, 1_048_576));
        var chunk = new byte[81_920];
        while (true)
        {
            var read = await stream.ReadAsync(chunk, token);
            if (read == 0) break;
            if (buffer.Length + read > limit) throw new InvalidDataException($"Oversized payload exceeds maximum {limit} bytes");
            await buffer.WriteAsync(chunk.AsMemory(0, read), token);
        }
        return buffer.ToArray();
    }

    private static bool LooksBinary(ReadOnlySpan<byte> payload)
    {
        if (payload.Length == 0) return false;
        var sample = payload[..Math.Min(payload.Length, 8192)];
        var suspicious = 0;
        foreach (var value in sample) if (value == 0 || (value < 9 && value is not (9 or 10 or 13))) suspicious++;
        return suspicious > sample.Length / 100;
    }

    private static string DecodeText(byte[] payload) => Encoding.UTF8.GetString(payload);

    private static ProxySourceResult Success(ProxySourceDefinition definition, string content, byte[] payload,
        int attempts, TimeSpan duration, int status, string? contentType, string? etag, DateTimeOffset? lastModified,
        bool fromCache, ISourceContentFingerprintService fingerprints) => new()
    {
        SourceName = definition.Name, Success = true, Content = content, Attempts = attempts, Duration = duration,
        HttpStatus = status, ContentType = contentType, ContentBytes = payload.LongLength,
        ContentSha256 = fingerprints.ComputeSha256(payload), ETag = etag, LastModified = lastModified, FromCache = fromCache
    };

    private static ProxySourceResult Failure(ProxySourceDefinition definition, string error, int attempts, TimeSpan duration,
        int? status = null, string? contentType = null, long contentBytes = 0) =>
        new() { SourceName = definition.Name, Error = error, Attempts = attempts, Duration = duration,
            HttpStatus = status, ContentType = contentType, ContentBytes = contentBytes };
}

public sealed class TextProxySource(IHttpClientFactory factory, HunterOptions options, SourcePayloadCache cache,
    ISourceContentFingerprintService fingerprints, ILogger<TextProxySource> logger)
    : RemoteProxySource(factory, options, cache, fingerprints, logger)
{
    protected override IReadOnlySet<string> Formats { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "text", "github-raw" };
}

public sealed class CsvProxySource(IHttpClientFactory factory, HunterOptions options, SourcePayloadCache cache,
    ISourceContentFingerprintService fingerprints, ILogger<CsvProxySource> logger)
    : RemoteProxySource(factory, options, cache, fingerprints, logger)
{
    protected override IReadOnlySet<string> Formats { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "csv" };
}

public sealed class JsonProxySource(IHttpClientFactory factory, HunterOptions options, SourcePayloadCache cache,
    ISourceContentFingerprintService fingerprints, ILogger<JsonProxySource> logger)
    : RemoteProxySource(factory, options, cache, fingerprints, logger)
{
    protected override IReadOnlySet<string> Formats { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "json" };
}

public sealed class HtmlProxySource(IHttpClientFactory factory, HunterOptions options, SourcePayloadCache cache,
    ISourceContentFingerprintService fingerprints, ILogger<HtmlProxySource> logger)
    : RemoteProxySource(factory, options, cache, fingerprints, logger)
{
    protected override IReadOnlySet<string> Formats { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "html" };
}

public sealed class LocalFileProxySource(HunterOptions options, ISourceContentFingerprintService fingerprints) : IProxySource
{
    public bool CanHandle(ProxySourceDefinition definition) => !string.IsNullOrWhiteSpace(definition.Path)
        || definition.Format.Equals("local-file", StringComparison.OrdinalIgnoreCase);

    public async Task<ProxySourceResult> LoadAsync(ProxySourceDefinition definition, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        if (string.IsNullOrWhiteSpace(definition.Path))
            return new ProxySourceResult { SourceName = definition.Name, Error = "Local source path is missing" };
        try
        {
            var info = new FileInfo(definition.Path);
            var limit = Math.Min(options.MaximumSourcePayloadBytes, definition.MaximumDownloadBytes > 0
                ? definition.MaximumDownloadBytes : options.MaximumSourcePayloadBytes);
            if (info.Length > limit)
                return new ProxySourceResult { SourceName = definition.Name, Error = $"Oversized payload: {info.Length} bytes", Attempts = 1, Duration = stopwatch.Elapsed, ContentBytes = info.Length };
            var payload = await File.ReadAllBytesAsync(definition.Path, cancellationToken);
            var content = Encoding.UTF8.GetString(payload);
            return new ProxySourceResult { SourceName = definition.Name, Success = true, Content = content, Attempts = 1,
                Duration = stopwatch.Elapsed, ContentBytes = payload.LongLength, ContentType = "text/plain",
                ContentSha256 = fingerprints.ComputeSha256(payload) };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new ProxySourceResult { SourceName = definition.Name, Error = ex.Message, Attempts = 1, Duration = stopwatch.Elapsed };
        }
    }
}

public static class JsonDefaults
{
    public static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
    };
    public static JsonSerializerOptions CompactOptions { get; } = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
    };
}
