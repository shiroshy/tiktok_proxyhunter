using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text.Json;
using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Infrastructure;

public sealed class ExitIpConsensusService
{
    public ExitIpResolutionResult Resolve(IEnumerable<ExitIpProviderResult> providerResults, string? directIp, int minimumProviders)
    {
        var results = providerResults.ToArray();
        var groups = results.Where(x => x.Status == ExitIpStatus.Resolved && IPAddress.TryParse(x.IpAddress, out _))
            .GroupBy(x => IPAddress.Parse(x.IpAddress!).ToString(), StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(x => x.Count()).ToArray();
        if (groups.Length == 0)
        {
            var status = results.Any(x => x.Status == ExitIpStatus.Timeout) ? ExitIpStatus.Timeout
                : results.Any(x => x.Status == ExitIpStatus.ProviderBlocked) ? ExitIpStatus.ProviderBlocked : ExitIpStatus.Unavailable;
            return new ExitIpResolutionResult { Status = status, DirectIp = directIp, Providers = results };
        }
        var winner = groups[0];
        if (winner.Count() < minimumProviders)
            return new ExitIpResolutionResult { Status = ExitIpStatus.ConsensusMismatch, ExitIp = winner.Key, DirectIp = directIp,
                Providers = results, Confidence = winner.Count() / (double)Math.Max(1, results.Length),
                ResolutionConfidence = ExitIpResolutionConfidence.SingleProvider };
        var ip = winner.Key;
        var same = IPAddress.TryParse(directIp, out var direct) && direct.Equals(IPAddress.Parse(ip));
        return new ExitIpResolutionResult
        {
            Status = same ? ExitIpStatus.SameAsDirectIp : ExitIpStatus.Resolved, ExitIp = ip, DirectIp = directIp,
            IsTransparentOrIneffective = same, Confidence = winner.Count() / (double)Math.Max(1, results.Count(x => x.Status == ExitIpStatus.Resolved)),
            Providers = results, ResolutionConfidence = winner.Count() >= 3 ? ExitIpResolutionConfidence.High : ExitIpResolutionConfidence.Consensus
        };
    }
}

public sealed class ExitIpResolver(ProxyHttpsClient proxyClient, ProxyHttpClient proxyHttpClient, IHttpClientFactory factory,
    ExitIpOptions options, ExitIpConsensusService consensus, ExitIpProviderCircuitBreaker circuitBreaker) : IExitIpResolver, IExitIpProviderDiagnostics
{
    private readonly SemaphoreSlim _directGate = new(1, 1);
    private string? _directIp;

    public async Task<ExitIpResolutionResult> ResolveAsync(ProxyEndpoint endpoint, CancellationToken cancellationToken)
    {
        var direct = await ResolveDirectIpAsync(cancellationToken);
        var providerResults = new List<ExitIpProviderResult>();
        var attempts = new List<ExitIpResolutionAttempt>();
        var configured = options.Providers.Concat(options.CustomEchoEndpoints.Select((url, index) => new ExitIpProvider
        { Name = $"custom-echo-{index + 1}", Family = $"custom-echo-{index + 1}", Url = url, ParserType = "auto",
          Priority = 100, TrustWeight = 1, TimeoutSeconds = 8 })).ToArray();
        var providers = ExitIpProviderPlanner.Select(configured, circuitBreaker, options.MaximumAttemptsPerProxy);
        foreach (var provider in providers)
        {
            var watch = Stopwatch.StartNew();
            ExitIpProviderResult result;
            int? httpStatus = null; string? contentType = null;
            try
            {
                var response = await proxyClient.GetAsync(endpoint, new Uri(provider.Url), cancellationToken, 16_384);
                httpStatus = response.StatusCode;
                response.Headers.TryGetValue("content-type", out contentType);
                if (response.StatusCode is 401 or 403 or 429)
                    result = new(provider.Name, ExitIpStatus.ProviderBlocked, null, watch.Elapsed, $"HTTP {response.StatusCode}");
                else if (TryParseIp(response.Body, provider.JsonField, out var ip))
                    result = new(provider.Name, ExitIpStatus.Resolved, ip, watch.Elapsed);
                else result = new(provider.Name, ExitIpStatus.InvalidResponse, null, watch.Elapsed, "No valid IP in response");
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            { result = new(provider.Name, ExitIpStatus.Timeout, null, watch.Elapsed, "Timeout"); }
            catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException
                or System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException)
            { result = new(provider.Name, ex is InvalidDataException ? ExitIpStatus.InvalidResponse : ExitIpStatus.Unavailable,
                null, watch.Elapsed, ex.Message); }
            providerResults.Add(result);
            circuitBreaker.Record(provider.Name, result.Status, httpStatus, result.Reason, options);
            attempts.Add(new() { Provider = provider.Name, ProviderFamily = Family(provider),
                Method = provider.Name.StartsWith("custom-echo-", StringComparison.OrdinalIgnoreCase)
                    ? ExitIpResolutionMethod.CustomEchoEndpoint : ExitIpResolutionMethod.ExternalHttpsProvider,
                Status = result.Status, IpAddress = result.IpAddress, HttpStatus = httpStatus, ContentType = contentType,
                Duration = watch.Elapsed, Reason = result.Reason });
            if (result.Status != ExitIpStatus.Resolved && Uri.TryCreate(provider.HttpUrl, UriKind.Absolute, out var httpUrl)
                && httpUrl.Scheme == Uri.UriSchemeHttp)
            {
                var httpWatch = Stopwatch.StartNew(); ExitIpProviderResult httpResult; int? fallbackStatus = null; string? fallbackType = null;
                try
                {
                    var response = await proxyHttpClient.GetAsync(endpoint, httpUrl, cancellationToken, 16_384);
                    fallbackStatus = response.StatusCode; response.Headers.TryGetValue("content-type", out fallbackType);
                    if (response.StatusCode is 401 or 403 or 429)
                        httpResult = new(provider.Name, ExitIpStatus.ProviderBlocked, null, httpWatch.Elapsed, $"HTTP {response.StatusCode}");
                    else if (TryParseIp(response.Body, provider.JsonField, out var fallbackIp))
                        httpResult = new(provider.Name, ExitIpStatus.Resolved, fallbackIp, httpWatch.Elapsed);
                    else httpResult = new(provider.Name, ExitIpStatus.InvalidResponse, null, httpWatch.Elapsed, "No valid IP in HTTP fallback response");
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                { httpResult = new(provider.Name, ExitIpStatus.Timeout, null, httpWatch.Elapsed, "HTTP fallback timeout"); }
                catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException
                    or System.Net.Sockets.SocketException)
                { httpResult = new(provider.Name, ex is InvalidDataException ? ExitIpStatus.InvalidResponse : ExitIpStatus.Unavailable,
                    null, httpWatch.Elapsed, ex.Message); }
                providerResults.Add(httpResult); circuitBreaker.Record(provider.Name, httpResult.Status, fallbackStatus, httpResult.Reason, options);
                attempts.Add(new() { Provider = provider.Name, ProviderFamily = Family(provider), Method = ExitIpResolutionMethod.ExternalHttpProvider,
                    Status = httpResult.Status, IpAddress = httpResult.IpAddress, HttpStatus = fallbackStatus, ContentType = fallbackType,
                    Duration = httpWatch.Elapsed, Reason = httpResult.Reason });
            }
            var partial = consensus.Resolve(providerResults, direct, options.MinimumConsensusProviders);
            if (partial.Status is ExitIpStatus.Resolved or ExitIpStatus.SameAsDirectIp) return partial with { Attempts = attempts };
        }
        return consensus.Resolve(providerResults, direct, options.MinimumConsensusProviders) with { Attempts = attempts };
    }

    public async Task<string?> ResolveDirectIpAsync(CancellationToken cancellationToken)
    {
        if (_directIp is not null) return _directIp;
        await _directGate.WaitAsync(cancellationToken);
        try
        {
            if (_directIp is not null) return _directIp;
            var values = new List<string>();
            var client = factory.CreateClient("exit-ip-direct");
            foreach (var provider in options.Providers.Where(x => x.Enabled).Take(3))
            {
                try
                {
                    using var response = await client.GetAsync(provider.Url, cancellationToken);
                    if (!response.IsSuccessStatusCode) continue;
                    if (TryParseIp(await response.Content.ReadAsStringAsync(cancellationToken), provider.JsonField, out var ip)) values.Add(ip!);
                }
                catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException) { if (cancellationToken.IsCancellationRequested) throw; }
            }
            _directIp = values.GroupBy(x => x).OrderByDescending(x => x.Count()).FirstOrDefault()?.Key;
            return _directIp;
        }
        finally { _directGate.Release(); }
    }

    public static bool TryParseIp(string content, string? jsonField, out string? ip)
    {
        ip = null; var candidate = content.Trim().Trim('"');
        if (!string.IsNullOrWhiteSpace(jsonField) || candidate.StartsWith('{'))
        {
            try
            {
                using var json = JsonDocument.Parse(content, new JsonDocumentOptions { MaxDepth = 16 });
                JsonElement value = default;
                var names = string.IsNullOrWhiteSpace(jsonField) ? new[] { "ip", "address", "origin" } : new[] { jsonField };
                if (!names.Any(name => json.RootElement.TryGetProperty(name, out value))) return false;
                candidate = value.ToString().Trim();
            }
            catch (JsonException) { return false; }
        }
        if (!IPAddress.TryParse(candidate, out var address)) return false;
        ip = address.ToString(); return true;
    }

    public IReadOnlyList<ExitIpProviderHealth> GetHealth() => circuitBreaker.Snapshot(options.Providers.Where(x => x.Enabled).Select(x => x.Name)
        .Concat(options.CustomEchoEndpoints.Select((_, index) => $"custom-echo-{index + 1}")));

    public async Task<IReadOnlyList<ExitIpResolutionAttempt>> TestDirectAsync(CancellationToken cancellationToken)
    {
        var attempts = new List<ExitIpResolutionAttempt>(); var client = factory.CreateClient("exit-ip-direct");
        var providers = options.Providers.Concat(options.CustomEchoEndpoints.Select((url, index) => new ExitIpProvider
        { Name = $"custom-echo-{index + 1}", Family = $"custom-echo-{index + 1}", Url = url,
          ParserType = "auto", Priority = 100, TrustWeight = 1, TimeoutSeconds = 8 })).ToArray();
        foreach (var provider in providers.Where(x => x.Enabled).OrderByDescending(x => x.Priority).ThenBy(x => x.Name))
        {
            var watch = Stopwatch.StartNew();
            try
            {
                using var response = await client.GetAsync(provider.Url, cancellationToken);
                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                string? ip = null;
                var valid = response.IsSuccessStatusCode && TryParseIp(body, provider.JsonField, out ip);
                var attempt = new ExitIpResolutionAttempt { Provider = provider.Name, ProviderFamily = Family(provider),
                    Method = ExitIpResolutionMethod.ExternalHttpsProvider, Status = valid ? ExitIpStatus.Resolved
                        : response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests ? ExitIpStatus.ProviderBlocked : ExitIpStatus.InvalidResponse,
                    IpAddress = valid ? ip : null, HttpStatus = (int)response.StatusCode, Duration = watch.Elapsed,
                    ContentType = response.Content.Headers.ContentType?.MediaType, Reason = valid ? null : $"HTTP {(int)response.StatusCode} or invalid body" };
                attempts.Add(attempt); circuitBreaker.Record(provider.Name, attempt.Status, attempt.HttpStatus, attempt.Reason, options);
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
            { if (cancellationToken.IsCancellationRequested) throw; var attempt = new ExitIpResolutionAttempt { Provider = provider.Name,
                ProviderFamily = Family(provider), Method = ExitIpResolutionMethod.ExternalHttpsProvider,
                Status = ex is OperationCanceledException ? ExitIpStatus.Timeout : ExitIpStatus.Unavailable,
                Duration = watch.Elapsed, Reason = ex.GetType().Name }; attempts.Add(attempt);
              circuitBreaker.Record(provider.Name, attempt.Status, null, attempt.Reason, options); }
        }
        return attempts;
    }

    private static string Family(ExitIpProvider provider) => string.IsNullOrWhiteSpace(provider.Family) ? provider.Name : provider.Family;
}

public sealed class ExitIpProviderCircuitBreaker
{
    private readonly ConcurrentDictionary<string, State> _states = new(StringComparer.OrdinalIgnoreCase);

    public bool CanUse(string provider, DateTimeOffset now) => !_states.TryGetValue(provider, out var state)
        || state.CooldownUntil is null || state.CooldownUntil <= now;

    public void Record(string provider, ExitIpStatus status, int? httpStatus, string? error, ExitIpOptions options)
    {
        var state = _states.GetOrAdd(provider, _ => new());
        lock (state)
        {
            if (status == ExitIpStatus.Resolved) { state.Successes++; state.ConsecutiveFailures = 0; state.Status = ExitIpProviderHealthStatus.Healthy; state.LastError = null; return; }
            // A tunnel/socket failure is normally proxy-specific. It must not globally trip a provider
            // for every later proxy in the run when no HTTP response was observed.
            if (httpStatus is null && status is ExitIpStatus.Timeout or ExitIpStatus.Unavailable)
            { state.Status = ExitIpProviderHealthStatus.Degraded; state.LastError = error; return; }
            state.ConsecutiveFailures++; state.LastError = error;
            if (httpStatus == 429) { state.RateLimits++; state.Status = ExitIpProviderHealthStatus.RateLimited;
                state.CooldownUntil = DateTimeOffset.UtcNow.AddSeconds(options.RateLimitCooldownSeconds); }
            else if (state.ConsecutiveFailures >= options.CircuitBreakerFailureThreshold)
            { state.Status = ExitIpProviderHealthStatus.TemporarilyDisabled; state.CooldownUntil = DateTimeOffset.UtcNow.AddSeconds(options.RateLimitCooldownSeconds); }
            else state.Status = status == ExitIpStatus.InvalidResponse ? ExitIpProviderHealthStatus.InvalidResponse
                : status == ExitIpStatus.Unavailable ? ExitIpProviderHealthStatus.Unavailable : ExitIpProviderHealthStatus.Degraded;
        }
    }

    public IReadOnlyList<ExitIpProviderHealth> Snapshot(IEnumerable<string> providers) => providers.Distinct(StringComparer.OrdinalIgnoreCase)
        .Select(name => _states.TryGetValue(name, out var state) ? state.Snapshot(name) : new ExitIpProviderHealth
        { Provider = name, Status = ExitIpProviderHealthStatus.Healthy }).ToArray();

    private sealed class State
    {
        public ExitIpProviderHealthStatus Status = ExitIpProviderHealthStatus.Healthy;
        public int Successes; public int ConsecutiveFailures; public int RateLimits;
        public DateTimeOffset? CooldownUntil; public string? LastError;
        public ExitIpProviderHealth Snapshot(string name) { lock (this) return new() { Provider = name, Status = Status,
            Successes = Successes, ConsecutiveFailures = ConsecutiveFailures, RateLimitResponses = RateLimits,
            CooldownUntil = CooldownUntil, LastError = LastError }; }
    }
}

public static class ExitIpProviderPlanner
{
    public static IReadOnlyList<ExitIpProvider> Select(IEnumerable<ExitIpProvider> providers,
        ExitIpProviderCircuitBreaker breaker, int maximumAttempts)
    {
        var seenFamilies = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        return providers.Where(x => x.Enabled && breaker.CanUse(x.Name, DateTimeOffset.UtcNow))
            .OrderByDescending(x => x.Priority).ThenByDescending(x => x.TrustWeight).ThenBy(x => x.Name)
            .OrderBy(x => seenFamilies.Add(string.IsNullOrWhiteSpace(x.Family) ? x.Name : x.Family) ? 0 : 1)
            .Take(Math.Max(1, maximumAttempts)).ToArray();
    }
}

public sealed class GeoConsensusService
{
    public ProxyGeoInfo Resolve(string ip, IEnumerable<ProxyGeoInfo> providerResults, int minimumProviders)
    {
        var results = providerResults.ToArray();
        var evidence = results.SelectMany(ToEvidence).ToArray();
        var groups = evidence.Where(x => !x.IsError && !string.IsNullOrWhiteSpace(x.CountryCode))
            .GroupBy(x => x.CountryCode!.ToUpperInvariant()).OrderByDescending(x => x.Sum(y => y.TrustWeight)).ThenBy(x => x.Key).ToArray();
        if (groups.Length == 0) return new ProxyGeoInfo { IpAddress = ip, Status = ProxyGeoStatus.Unavailable,
            Decision = GeoResolutionDecision.Unknown, ConfidenceLevel = GeoConfidenceLevel.Unknown,
            Risk = GeoRiskClassification.Unverified, Evidence = evidence,
            FieldResolutions = ResolveFields(evidence), Sources = results.SelectMany(x => x.Sources).Distinct().ToArray() };
        var winner = groups[0];
        var countryConflict = groups.Length > 1;
        var trustedSingle = winner.Count() == 1 && winner.First().TrustWeight >= 1;
        var confirmed = !countryConflict && (winner.Count() >= minimumProviders || trustedSingle);
        var decision = countryConflict ? GeoResolutionDecision.Conflicting
            : winner.Key.Equals("RU", StringComparison.OrdinalIgnoreCase)
                ? confirmed ? GeoResolutionDecision.ConfirmedRussia : GeoResolutionDecision.LikelyRussia
                : confirmed ? GeoResolutionDecision.ConfirmedNonRussia : GeoResolutionDecision.LikelyNonRussia;
        var confidence = countryConflict ? GeoConfidenceLevel.Conflicting
            : trustedSingle ? GeoConfidenceLevel.Verified
            : winner.Count() >= minimumProviders ? GeoConfidenceLevel.High : GeoConfidenceLevel.Low;
        var sourceInfo = results.Where(x => x.CountryCode?.Equals(winner.Key, StringComparison.OrdinalIgnoreCase) == true)
            .OrderByDescending(CountFields).FirstOrDefault();
        return (sourceInfo ?? new ProxyGeoInfo { IpAddress = ip }) with
        {
            Status = winner.Count() >= minimumProviders || trustedSingle ? ProxyGeoStatus.Resolved : ProxyGeoStatus.GeoUncertain,
            CountryCode = winner.Key, Decision = decision, ConfidenceLevel = confidence,
            Risk = decision is GeoResolutionDecision.ConfirmedRussia or GeoResolutionDecision.LikelyRussia
                ? GeoRiskClassification.RejectedRussia : decision == GeoResolutionDecision.Conflicting
                    ? GeoRiskClassification.Conflicting : GeoRiskClassification.NonRussian,
            Sources = evidence.Select(x => x.Provider).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            Confidence = winner.Sum(x => x.TrustWeight) / Math.Max(0.0001, evidence.Where(x => !x.IsError).Sum(x => x.TrustWeight)),
            Evidence = evidence, FieldResolutions = ResolveFields(evidence)
        };
    }

    private static int CountFields(ProxyGeoInfo x) => new[] { x.CountryName, x.Region, x.City, x.Asn, x.Organization, x.Timezone }.Count(v => !string.IsNullOrEmpty(v));

    private static IEnumerable<GeoEvidence> ToEvidence(ProxyGeoInfo result)
    {
        if (result.Evidence.Count > 0) return result.Evidence;
        var sources = result.Sources.Count > 0 ? result.Sources : ["unknown"];
        return sources.Select(source => new GeoEvidence
        {
            Provider = source, CountryCode = result.CountryCode, Asn = result.Asn,
            Organization = result.Organization, IsHosting = result.IsHosting,
            RawConfidence = result.Confidence, TrustWeight = 0.5,
            Timestamp = result.ResolvedAt, IsError = result.Status != ProxyGeoStatus.Resolved,
            IsRateLimited = result.Status == ProxyGeoStatus.ProviderBlocked,
            Error = result.Status == ProxyGeoStatus.Resolved ? null : result.Status.ToString()
        });
    }

    private static IReadOnlyDictionary<GeoEvidenceField, GeoFieldResolution> ResolveFields(IReadOnlyList<GeoEvidence> evidence)
    {
        var result = new Dictionary<GeoEvidenceField, GeoFieldResolution>();
        Resolve(GeoEvidenceField.CountryCode, x => x.CountryCode);
        Resolve(GeoEvidenceField.Asn, x => x.Asn);
        Resolve(GeoEvidenceField.Organization, x => x.Organization);
        Resolve(GeoEvidenceField.NetworkPrefix, x => x.NetworkPrefix);
        Resolve(GeoEvidenceField.Hosting, x => x.IsHosting?.ToString());
        return result;

        void Resolve(GeoEvidenceField field, Func<GeoEvidence, string?> selector)
        {
            var groups = evidence.Where(x => !x.IsError).Select(x => (Evidence: x, Value: selector(x)))
                .Where(x => !string.IsNullOrWhiteSpace(x.Value)).GroupBy(x => x.Value!, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(x => x.Sum(y => y.Evidence.TrustWeight)).ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase).ToArray();
            if (groups.Length == 0) { result[field] = new() { Field = field, Confidence = GeoConfidenceLevel.Unknown }; return; }
            var best = groups[0];
            result[field] = new GeoFieldResolution { Field = field, Value = best.Key,
                Confidence = groups.Length > 1 ? GeoConfidenceLevel.Conflicting : best.Count() > 1 ? GeoConfidenceLevel.High
                    : best.First().Evidence.TrustWeight >= 1 ? GeoConfidenceLevel.Verified : GeoConfidenceLevel.Low,
                Providers = best.Select(x => x.Evidence.Provider).Distinct(StringComparer.OrdinalIgnoreCase).ToArray() };
        }
    }
}

public sealed class ProxyGeoResolver(IHttpClientFactory factory, GeoOptions options, GeoConsensusService consensus,
    ILocalGeoIpProvider localProvider) : IProxyGeoResolver
{
    private readonly ConcurrentDictionary<string, Lazy<Task<ProxyGeoInfo>>> _cache = new(StringComparer.OrdinalIgnoreCase);

    public Task<ProxyGeoInfo> ResolveAsync(string exitIp, CancellationToken cancellationToken)
    {
        if (!IPAddress.TryParse(exitIp, out var address)) return Task.FromResult(new ProxyGeoInfo { IpAddress = exitIp, Status = ProxyGeoStatus.InvalidResponse });
        var canonical = address.ToString();
        return _cache.GetOrAdd(canonical, _ => new Lazy<Task<ProxyGeoInfo>>(() => ResolveCoreAsync(canonical, cancellationToken))).Value;
    }

    private async Task<ProxyGeoInfo> ResolveCoreAsync(string ip, CancellationToken cancellationToken)
    {
        if (!options.Enabled) return new ProxyGeoInfo { IpAddress = ip, Status = ProxyGeoStatus.Unavailable };
        var results = new List<ProxyGeoInfo>(); var client = factory.CreateClient("geo-providers");
        if (options.LocalDatabase.Enabled)
        {
            var local = await localProvider.ResolveAsync(ip, cancellationToken);
            results.Add(new ProxyGeoInfo { IpAddress = ip,
                Status = local.IsError ? ProxyGeoStatus.Unavailable : ProxyGeoStatus.Resolved,
                CountryCode = local.CountryCode, Asn = local.Asn, Organization = local.Organization,
                IsHosting = local.IsHosting, Sources = [local.Provider], Evidence = [local] });
        }
        foreach (var provider in options.Providers.Where(x => x.Enabled))
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(provider.TimeoutSeconds));
            try
            {
                var url = provider.UrlTemplate.Replace("{ip}", Uri.EscapeDataString(ip), StringComparison.Ordinal);
                using var response = await client.GetAsync(url, timeout.Token);
                if (!response.IsSuccessStatusCode) { results.Add(Error(provider, ip, ProxyGeoStatus.ProviderBlocked, $"HTTP {(int)response.StatusCode}", response.StatusCode == HttpStatusCode.TooManyRequests)); continue; }
                var content = await response.Content.ReadAsStringAsync(timeout.Token);
                results.Add(ParseProvider(provider.Name, ip, content, provider.TrustWeight));
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            { results.Add(Error(provider, ip, ProxyGeoStatus.Timeout, "Timeout")); }
            catch (HttpRequestException)
            { results.Add(Error(provider, ip, ProxyGeoStatus.Unavailable, "Network error")); }
        }
        return consensus.Resolve(ip, results, options.MinimumConsensusProviders);
    }

    public static ProxyGeoInfo ParseProvider(string provider, string ip, string content, double trustWeight = 0.5)
    {
        try
        {
            using var json = JsonDocument.Parse(content, new JsonDocumentOptions { MaxDepth = 32 });
            var root = json.RootElement;
            string? Get(params string[] names)
            {
                foreach (var name in names)
                    if (root.TryGetProperty(name, out var value) && value.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined)) return value.ToString();
                return null;
            }
            string? GetNested(string parent, params string[] names)
            {
                if (!root.TryGetProperty(parent, out var node) || node.ValueKind != JsonValueKind.Object) return null;
                foreach (var name in names)
                    if (node.TryGetProperty(name, out var value) && value.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined)) return value.ToString();
                return null;
            }
            var code = Get("country_code", "countryCode", "country_code2");
            var asn = Get("asn", "connection_asn") ?? GetNested("connection", "asn");
            var organization = Get("org", "organization", "isp") ?? GetNested("connection", "org", "isp");
            var hosting = TryBool(root, "hosting", "is_hosting");
            var status = string.IsNullOrEmpty(code) ? ProxyGeoStatus.InvalidResponse : ProxyGeoStatus.Resolved;
            var evidence = new GeoEvidence { Provider = provider, CountryCode = code?.ToUpperInvariant(), Asn = asn,
                Organization = organization, NetworkPrefix = Get("network", "network_prefix"), IsHosting = hosting,
                RawConfidence = string.IsNullOrEmpty(code) ? 0 : 1, TrustWeight = trustWeight,
                IsError = status != ProxyGeoStatus.Resolved, Error = status == ProxyGeoStatus.Resolved ? null : "Missing country code" };
            return new ProxyGeoInfo { IpAddress = ip, Status = status,
                CountryCode = code?.ToUpperInvariant(), CountryName = Get("country", "country_name"), Region = Get("region", "region_name"),
                City = Get("city"), Asn = asn, Organization = organization,
                IsHosting = hosting, Timezone = Get("timezone") ?? GetNested("timezone", "id", "utc"), Sources = [provider], Evidence = [evidence] };
        }
        catch (JsonException) { return new ProxyGeoInfo { IpAddress = ip, Status = ProxyGeoStatus.InvalidResponse, Sources = [provider] }; }
    }

    private static bool? TryBool(JsonElement root, params string[] names)
    { foreach (var name in names) if (root.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False) return value.GetBoolean(); return null; }

    private static ProxyGeoInfo Error(GeoProvider provider, string ip, ProxyGeoStatus status, string reason, bool rateLimited = false) =>
        new() { IpAddress = ip, Status = status, Sources = [provider.Name], Evidence = [new GeoEvidence
        { Provider = provider.Name, TrustWeight = provider.TrustWeight, IsError = true, IsRateLimited = rateLimited, Error = reason }] };
}

public static class GeoPolicy
{
    public static bool IsRejected(ProxyGeoInfo? geo, GeoOptions options) => geo?.CountryCode is { } code
        ? options.RejectCountryCodes.Contains(code, StringComparer.OrdinalIgnoreCase)
        : !options.AllowUnknownCountry;

    public static bool IsFastCheckEligible(ProxyGeoInfo? geo, GeoOptions options) => IsCountryDecisionRejected(geo, options) ? false : geo?.Decision switch
    {
        GeoResolutionDecision.ConfirmedRussia or GeoResolutionDecision.LikelyRussia => true,
        GeoResolutionDecision.ConfirmedNonRussia or GeoResolutionDecision.LikelyNonRussia => true,
        GeoResolutionDecision.Conflicting => options.AllowConflictingCountryForFastCheck,
        _ => options.AllowUnknownCountryForFastCheck
    };

    public static bool IsBrowserEligible(ProxyGeoInfo? geo, GeoOptions options) => IsCountryDecisionRejected(geo, options) ? false : geo?.Decision switch
    {
        GeoResolutionDecision.ConfirmedRussia or GeoResolutionDecision.LikelyRussia => true,
        GeoResolutionDecision.Conflicting => options.AllowConflictingCountryForBrowserCheck,
        GeoResolutionDecision.Unknown or null => options.AllowUnknownCountryForBrowserCheck,
        _ => true
    };

    public static bool IsRecommendationEligible(ProxyGeoInfo? geo, GeoOptions options)
    {
        if (IsCountryDecisionRejected(geo, options)) return false;
        if (geo is null || geo.Decision is GeoResolutionDecision.Unknown or GeoResolutionDecision.Conflicting)
            return options.AllowUnknownCountryForRecommendation && MeetsConfidence(geo?.ConfidenceLevel ?? GeoConfidenceLevel.Unknown, options.MinimumConfidenceForRecommendation);
        return geo.Decision is GeoResolutionDecision.ConfirmedNonRussia or GeoResolutionDecision.LikelyNonRussia
            && MeetsConfidence(geo.ConfidenceLevel, options.MinimumConfidenceForRecommendation);
    }

    public static bool IsCountryDecisionRejected(ProxyGeoInfo? geo, GeoOptions options)
    {
        if (geo is null) return false;
        if (geo.Decision == GeoResolutionDecision.ConfirmedRussia) return true;
        if (geo.Decision == GeoResolutionDecision.LikelyRussia)
            return options.RejectLikelyCountryCodes.Contains("RU", StringComparer.OrdinalIgnoreCase);
        if (geo.CountryCode is not { } code) return false;
        return geo.Decision == GeoResolutionDecision.ConfirmedNonRussia
            ? options.RejectConfirmedCountryCodes.Contains(code, StringComparer.OrdinalIgnoreCase)
            : geo.Decision == GeoResolutionDecision.LikelyNonRussia
                && options.RejectLikelyCountryCodes.Contains(code, StringComparer.OrdinalIgnoreCase);
    }

    public static bool MeetsConfidence(GeoConfidenceLevel actual, GeoConfidenceLevel minimum)
    {
        static int Rank(GeoConfidenceLevel value) => value switch
        { GeoConfidenceLevel.Verified => 4, GeoConfidenceLevel.High => 3, GeoConfidenceLevel.Medium => 2, GeoConfidenceLevel.Low => 1, _ => 0 };
        return Rank(actual) >= Rank(minimum);
    }
}
