using System.Security.Cryptography;
using System.Text;
using TikTokProxyHunter.Core;
using Microsoft.Extensions.Logging;

namespace TikTokProxyHunter.Infrastructure;

public sealed class SourceContentFingerprintService : ISourceContentFingerprintService
{
    public string ComputeSha256(ReadOnlySpan<byte> content) => Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();

    public IReadOnlyDictionary<string, string> FindExactMirrors(IEnumerable<ProxySourceHealth> sources)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in sources.Where(x => !string.IsNullOrEmpty(x.ContentSha256))
                     .GroupBy(x => x.ContentSha256!, StringComparer.OrdinalIgnoreCase))
        {
            var canonical = group.OrderBy(x => x.SourceName, StringComparer.OrdinalIgnoreCase).First().SourceName;
            foreach (var duplicate in group.Where(x => !x.SourceName.Equals(canonical, StringComparison.OrdinalIgnoreCase)))
                result[duplicate.SourceName] = canonical;
        }
        return result;
    }
}

public sealed class SourceHealthEvaluator : ISourceHealthEvaluator
{
    public ProxySourceHealth Evaluate(ProxySourceDefinition definition, ProxySourceResult result,
        int extractedRows, int validCandidates, int consecutiveFailures, string? duplicateOf = null)
    {
        var percentage = extractedRows == 0 ? 0 : validCandidates * 100d / extractedRows;
        var status = Classify(definition, result, extractedRows, validCandidates, percentage, duplicateOf);
        return new ProxySourceHealth
        {
            SourceName = definition.Name, SourceFamily = definition.SourceFamily, Status = status,
            HttpStatus = result.HttpStatus, ContentType = result.ContentType, ContentBytes = result.ContentBytes,
            DownloadTime = result.Duration, ExtractedRows = extractedRows, ValidCandidates = validCandidates,
            ValidPercentage = percentage, ContentSha256 = result.ContentSha256,
            LastSuccess = result.Success ? DateTimeOffset.UtcNow : null,
            ConsecutiveFailures = result.Success ? 0 : consecutiveFailures,
            DuplicateOf = duplicateOf, Reason = result.Error, FromCache = result.FromCache
        };
    }

    public static ProxySourceHealthStatus Classify(ProxySourceDefinition definition, ProxySourceResult result,
        int extractedRows, int validCandidates, double validPercentage, string? duplicateOf = null)
    {
        if (!definition.Enabled) return ProxySourceHealthStatus.Disabled;
        if (result.HttpStatus == 429 || Contains(result.Error, "rate limit")) return ProxySourceHealthStatus.RateLimited;
        if (result.HttpStatus is 401 or 403 || Contains(result.Error, "authorization") || Contains(result.Error, "authentication"))
            return ProxySourceHealthStatus.AuthenticationRequired;
        if (Contains(result.Error, "captcha") || Contains(result.Error, "challenge")) return ProxySourceHealthStatus.Captcha;
        if (Contains(result.Error, "oversized") || Contains(result.Error, "maximum payload")) return ProxySourceHealthStatus.Oversized;
        if (Contains(result.Error, "binary") || Contains(result.Error, "suspicious")) return ProxySourceHealthStatus.SuspiciousContent;
        if (!result.Success) return ProxySourceHealthStatus.Unavailable;
        if (result.ContentBytes == 0 || extractedRows == 0) return ProxySourceHealthStatus.Empty;
        if (validCandidates == 0) return ProxySourceHealthStatus.InvalidFormat;
        if (!string.IsNullOrEmpty(definition.ExpectedContentType)
            && !(result.ContentType ?? string.Empty).StartsWith(definition.ExpectedContentType, StringComparison.OrdinalIgnoreCase))
            return ProxySourceHealthStatus.SuspiciousContent;
        if (validCandidates < definition.MinimumExpectedCandidates || validPercentage < 50 || duplicateOf is not null)
            return ProxySourceHealthStatus.Degraded;
        return ProxySourceHealthStatus.Healthy;
    }

    private static bool Contains(string? value, string term) => value?.Contains(term, StringComparison.OrdinalIgnoreCase) == true;
}

public sealed record SourceCacheEntry(string? ETag, DateTimeOffset? LastModified, byte[] Payload);

public sealed class SourcePayloadCache(ISourceContentFingerprintService fingerprints, string? directory = null,
    ILogger<SourcePayloadCache>? logger = null)
{
    private readonly string _directory = directory ?? Path.Combine(".cache", "proxy-sources");

    public async Task<SourceCacheEntry?> GetAsync(Uri uri, CancellationToken token)
    {
        var key = fingerprints.ComputeSha256(Encoding.UTF8.GetBytes(uri.AbsoluteUri));
        var metadataPath = Path.Combine(_directory, key + ".json");
        var payloadPath = Path.Combine(_directory, key + ".payload");
        if (!File.Exists(metadataPath) || !File.Exists(payloadPath)) return null;
        try
        {
            var metadata = System.Text.Json.JsonSerializer.Deserialize<CacheMetadata>(
                await File.ReadAllTextAsync(metadataPath, token), JsonDefaults.Options);
            if (metadata is null) return null;
            return new SourceCacheEntry(metadata.ETag, metadata.LastModified, await File.ReadAllBytesAsync(payloadPath, token));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            logger?.LogDebug("Ignoring unreadable source cache entry for {Uri}: {Reason}", uri, ex.Message);
            return null;
        }
    }

    public async Task SaveAsync(Uri uri, string? etag, DateTimeOffset? lastModified, byte[] payload, CancellationToken token)
    {
        Directory.CreateDirectory(_directory);
        var key = fingerprints.ComputeSha256(Encoding.UTF8.GetBytes(uri.AbsoluteUri));
        await File.WriteAllBytesAsync(Path.Combine(_directory, key + ".payload"), payload, token);
        await File.WriteAllTextAsync(Path.Combine(_directory, key + ".json"),
            System.Text.Json.JsonSerializer.Serialize(new CacheMetadata(etag, lastModified), JsonDefaults.Options), token);
    }

    private sealed record CacheMetadata(string? ETag, DateTimeOffset? LastModified);
}
