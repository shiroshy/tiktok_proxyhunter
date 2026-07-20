namespace TikTokProxyHunter.Core;

public interface IProxySource
{
    bool CanHandle(ProxySourceDefinition definition);
    Task<ProxySourceResult> LoadAsync(ProxySourceDefinition definition, CancellationToken cancellationToken);
}

public interface IProxySourceLoader
{
    Task<IReadOnlyList<ProxySourceDefinition>> LoadDefinitionsAsync(string path, CancellationToken cancellationToken);
    Task<IReadOnlyList<ProxySourceResult>> LoadEnabledAsync(IEnumerable<ProxySourceDefinition> definitions, CancellationToken cancellationToken);
}

public interface IProxyParser
{
    bool CanParse(string format);
    IReadOnlyList<ProxyCandidate> Parse(ProxySourceDefinition source, string content);
}

public interface IProxyNormalizer
{
    bool TryNormalize(ProxyCandidate candidate, out ProxyEndpoint? endpoint, out string? rejectionReason);
}

public interface IProxyDeduplicator
{
    IReadOnlyList<ProxyEndpoint> Deduplicate(IEnumerable<ProxyEndpoint> endpoints);
}

public interface IProxyProtocolDetector
{
    Task<ProxyProbeResult> DetectAsync(ProxyEndpoint endpoint, CancellationToken cancellationToken);
}

public interface IProxyProbe
{
    Task<ProxyProbeResult> ProbeAsync(ProxyEndpoint endpoint, ProxyProtocol protocol, string targetHost, int targetPort, CancellationToken cancellationToken);
}

public interface ITikTokChecker
{
    Task<TikTokCheckResult> CheckAsync(ProxyEndpoint endpoint, Uri url, CancellationToken cancellationToken);
}

public interface IProxyScorer
{
    ProxyScore Calculate(ProxyCheckResult result);
}

public interface IResultExporter
{
    Task ExportAsync(string outputDirectory, IReadOnlyList<ProxyCandidate> candidates,
        IReadOnlyList<ProxyEndpoint> normalized, IReadOnlyList<ProxyCheckResult> checks,
        RunSummary summary, CancellationToken cancellationToken);
}

public interface ISourceHealthEvaluator
{
    ProxySourceHealth Evaluate(ProxySourceDefinition definition, ProxySourceResult result,
        int extractedRows, int validCandidates, int consecutiveFailures, string? duplicateOf = null);
}

public interface ISourceContentFingerprintService
{
    string ComputeSha256(ReadOnlySpan<byte> content);
    IReadOnlyDictionary<string, string> FindExactMirrors(IEnumerable<ProxySourceHealth> sources);
}

public interface IGitHubSourceDiscoveryService
{
    Task<SourceDiscoveryReport> DiscoverAsync(IReadOnlyList<ProxySourceDefinition> knownSources,
        string? tokenEnvironmentVariable, CancellationToken cancellationToken);
}

public interface IExitIpResolver
{
    Task<ExitIpResolutionResult> ResolveAsync(ProxyEndpoint endpoint, CancellationToken cancellationToken);
    Task<string?> ResolveDirectIpAsync(CancellationToken cancellationToken);
}

public interface IExitIpProviderDiagnostics
{
    IReadOnlyList<ExitIpProviderHealth> GetHealth();
    Task<IReadOnlyList<ExitIpResolutionAttempt>> TestDirectAsync(CancellationToken cancellationToken);
}

public interface IProxyGeoResolver
{
    Task<ProxyGeoInfo> ResolveAsync(string exitIp, CancellationToken cancellationToken);
}

public interface ILocalGeoIpProvider
{
    Task<GeoEvidence> ResolveAsync(string ipAddress, CancellationToken cancellationToken);
    Task<IReadOnlyList<GeoDatabaseValidationResult>> ValidateAsync(CancellationToken cancellationToken);
}

public interface IProxyPreScorer
{
    ProxyPreScore Calculate(ProxyCheckResult result);
}

public interface IBrowserDoctor
{
    Task<BrowserDoctorResult> DiagnoseAsync(CancellationToken cancellationToken);
}

public interface ITikTokCapabilityVerifier
{
    Task<IReadOnlyList<TikTokCapabilityResult>> VerifyFastAsync(ProxyEndpoint endpoint,
        IEnumerable<Uri> publicVideoUrls, CancellationToken cancellationToken);
    Task<TikTokCapabilityResult> VerifyCapabilityAsync(ProxyEndpoint endpoint, TikTokCapability capability,
        Uri? videoUrl, CancellationToken cancellationToken);
}

public interface IProxyStabilityChecker
{
    Task<ProxyStabilityResult> CheckAsync(ProxyEndpoint endpoint, CancellationToken cancellationToken);
    Task<ProxyStabilityResult> CheckAsync(ProxyEndpoint endpoint, TikTokCapability capability,
        Uri? videoUrl, CancellationToken cancellationToken);
}

public interface IBrowserProxyVerifier
{
    Task<BrowserVerificationResult> VerifyAsync(ProxyEndpoint endpoint, Uri videoUrl, CancellationToken cancellationToken);
}

public interface IAdvancedBrowserProxyVerifier
{
    Task<BrowserVerificationResult> VerifyAsync(ProxyEndpoint endpoint, Uri videoUrl,
        BrowserVerificationMode mode, CancellationToken cancellationToken);
}

public interface ITikTokEmbedPlayerVerifier
{
    Task<TikTokEmbedPlayerResult> VerifyAsync(ProxyEndpoint endpoint, Uri postUrl, CancellationToken cancellationToken);
}

public interface IRunCheckpointStore
{
    Task<RunCheckpoint?> LoadAsync(string path, CancellationToken cancellationToken);
    Task SaveAsync(string path, RunCheckpoint checkpoint, CancellationToken cancellationToken);
}

public interface IHunterRunObserver
{
    ValueTask OnProgressAsync(HunterRunProgress progress, CancellationToken cancellationToken);
}

public interface IHunterProgressSink
{
    ValueTask PublishAsync(HunterRunProgress progress, CancellationToken cancellationToken);
}

public interface IHunterRunService
{
    Task<HunterRunResult> RunAsync(HunterRunConfiguration configuration,
        IHunterRunObserver observer, CancellationToken cancellationToken);
}

public interface IHunterRunController
{
    HunterRunStatus Status { get; }
    bool IsRunActive { get; }
    Task<HunterRunResult> StartAsync(HunterRunConfiguration configuration,
        IHunterRunObserver observer, CancellationToken cancellationToken = default);
    Task CancelAsync();
}
