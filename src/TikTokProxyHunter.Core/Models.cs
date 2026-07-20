using System.Text.Json;
using System.Text.Json.Serialization;

namespace TikTokProxyHunter.Core;

[JsonConverter(typeof(JsonStringEnumConverter<ProxyProtocol>))]
public enum ProxyProtocol { Unknown, Http, HttpsConnect, Socks4, Socks4a, Socks5 }

[JsonConverter(typeof(JsonStringEnumConverter<TikTokStatus>))]
public enum TikTokStatus
{
    Accessible, AccessibleButBlocked, CaptchaOrChallenge, Forbidden, RateLimited,
    ProxyAuthenticationRequired, TlsFailure, Timeout, ConnectionFailure,
    InvalidContent, UnknownFailure
}

public sealed record ProxyEndpoint
{
    public required string Host { get; init; }
    public required int Port { get; init; }
    public ProxyProtocol DeclaredProtocol { get; init; }
    public ProxyProtocol DetectedProtocol { get; init; }
    public required string Source { get; init; }
    public DateTimeOffset RetrievedAt { get; init; } = DateTimeOffset.UtcNow;
    public string? Username { get; init; }
    public string? Password { get; init; }
    public required string NormalizedKey { get; init; }
    public IReadOnlyList<string> Sources { get; init; } = [];
    public IReadOnlyList<string> SourceFamilies { get; init; } = [];
    public int ObservationCount { get; init; } = 1;

    [JsonIgnore]
    public bool HasCredentials => !string.IsNullOrEmpty(Username) || !string.IsNullOrEmpty(Password);

    public override string ToString() => $"{DetectedProtocol}:{Host}:{Port}" +
        (HasCredentials ? " (credentials redacted)" : string.Empty);
}

public sealed record ProxyCandidate(
    string Host,
    int Port,
    ProxyProtocol DeclaredProtocol,
    string Source,
    DateTimeOffset RetrievedAt,
    string? Username = null,
    string? Password = null,
    string? Raw = null);

public sealed record ProxySourceDefinition
{
    public required string Name { get; init; }
    public bool Enabled { get; init; } = true;
    public string? Url { get; init; }
    public string? Path { get; init; }
    public string Format { get; init; } = "text";
    public ProxyProtocol DeclaredProtocol { get; init; }
    public int TimeoutSeconds { get; init; } = 20;
    public string Category { get; init; } = "Unspecified";
    public int Priority { get; init; } = 50;
    public double TrustWeight { get; init; } = 0.5;
    public string License { get; init; } = "Unknown";
    public string? Homepage { get; init; }
    public string? ExpectedContentType { get; init; }
    public long MaximumDownloadBytes { get; init; } = 52_428_800;
    public int MinimumExpectedCandidates { get; init; } = 1;
    public string? Notes { get; init; }
    public string? SourceFamily { get; init; }
    public Dictionary<string, JsonElement> ParserOptions { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed record ProxySourceResult
{
    public required string SourceName { get; init; }
    public bool Success { get; init; }
    public string? Content { get; init; }
    public string? Error { get; init; }
    public int Attempts { get; init; }
    public TimeSpan Duration { get; init; }
    public int CandidateCount { get; init; }
    public int? HttpStatus { get; init; }
    public string? ContentType { get; init; }
    public long ContentBytes { get; init; }
    public string? ContentSha256 { get; init; }
    public string? ETag { get; init; }
    public DateTimeOffset? LastModified { get; init; }
    public bool FromCache { get; init; }
}

public sealed record ProxyProbeResult
{
    public required ProxyEndpoint Endpoint { get; init; }
    public bool Success { get; init; }
    public ProxyProtocol Protocol { get; init; }
    public TimeSpan ConnectTime { get; init; }
    public TimeSpan TunnelTime { get; init; }
    public string? FailureReason { get; init; }
    public int? ResponseCode { get; init; }
    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;
}

public sealed record TikTokCheckResult
{
    public required Uri Url { get; init; }
    public TikTokStatus Status { get; init; }
    public bool TlsValid { get; init; }
    public TimeSpan ConnectionTime { get; init; }
    public TimeSpan TunnelTime { get; init; }
    public TimeSpan TlsHandshakeTime { get; init; }
    public TimeSpan TimeToFirstByte { get; init; }
    public TimeSpan TotalTime { get; init; }
    public int? HttpStatus { get; init; }
    public long ResponseBytes { get; init; }
    public string? FinalHost { get; init; }
    public string? FailureReason { get; init; }
    public IReadOnlyDictionary<string, string> ResponseHeaders { get; init; } = new Dictionary<string, string>();
}

public sealed record ProxyCheckResult
{
    public required ProxyEndpoint Endpoint { get; init; }
    public ProxyProbeResult? Probe { get; init; }
    public IReadOnlyList<TikTokCheckResult> TikTokChecks { get; init; } = [];
    public ProxyScore Score { get; init; } = new(0, []);
    public int SuccessfulChecks { get; init; }
    public ExitIpResolutionResult? ExitIp { get; init; }
    public ProxyGeoInfo? Geo { get; init; }
    public IReadOnlyList<TikTokCapabilityResult> TikTokCapabilities { get; init; } = [];
    public ProxyStabilityResult? Stability { get; init; }
    public BrowserVerificationResult? BrowserVerification { get; init; }
    public ProxyRecommendationClass RecommendationClass { get; init; } = ProxyRecommendationClass.Rejected;
    public ProxyPreScore PreScore { get; init; } = new(0, false, []);
    public TechnicalTikTokAccess TechnicalAccess { get; init; }
    public PlaybackCapability PlaybackCapability { get; init; }
    public RecommendationEligibility RecommendationEligibility { get; init; } = RecommendationEligibility.NoTechnicalAccess;
    public IReadOnlyList<TikTokEmbedPlayerResult> EmbedPlayerResults { get; init; } = [];
    public BrowserPlaybackSet BrowserPlayback { get; init; } = new();
    public ProxyStabilityResult? NetworkStability { get; init; }
    public ProxyStabilityResult? TikTokPageStability { get; init; }
    public ProxyStabilityResult? PlaybackStability { get; init; }
}

public sealed record ProxyScore(int Value, IReadOnlyList<string> Reasons);

public sealed record NormalizationOptions(bool AllowPrivateAddresses = false);

public sealed record HunterOptions
{
    public int CollectionConcurrency { get; init; } = 8;
    public int ProbeConcurrency { get; init; } = 100;
    public int PerSourceHostConcurrency { get; init; } = 2;
    public int SourceTimeoutSeconds { get; init; } = 20;
    public int ProxyConnectTimeoutSeconds { get; init; } = 5;
    public int TikTokRequestTimeoutSeconds { get; init; } = 12;
    public int Retries { get; init; } = 1;
    public bool AllowPrivateAddresses { get; init; }
    public long MaximumSourcePayloadBytes { get; init; } = 52_428_800;
    public int MaximumCandidates { get; init; } = 250_000;
    public int ChannelCapacity { get; init; } = 5_000;
    public int DeduplicationMemoryLimit { get; init; } = 1_000_000;
    public int CheckpointIntervalSeconds { get; init; } = 30;
    public int MaximumLineLength { get; init; } = 65_536;
    public string UserAgent { get; init; } = "TikTokProxyHunter/1.0 (+public-proxy-validation; no-circumvention)";
    public IReadOnlyList<ProxyProtocol> ProtocolDetectionOrder { get; init; } =
        [ProxyProtocol.Socks5, ProxyProtocol.HttpsConnect, ProxyProtocol.Socks4a, ProxyProtocol.Socks4, ProxyProtocol.Http];
    public IReadOnlyList<string> TikTokUrls { get; init; } = ["https://www.tiktok.com/", "https://m.tiktok.com/"];
    public ContentSignatures Signatures { get; init; } = new();
    public ScoreWeights Score { get; init; } = new();
}

public sealed record ContentSignatures
{
    public IReadOnlyList<string> Captcha { get; init; } = ["captcha", "verify you are human"];
    public IReadOnlyList<string> Challenge { get; init; } = ["cf-chl-", "challenge-platform", "just a moment"];
    public IReadOnlyList<string> AccessDenied { get; init; } = ["access denied", "request blocked"];
    public IReadOnlyList<string> ProxyError { get; init; } = ["proxy error", "tunnel connection failed", "connection reset"];
    public IReadOnlyList<string> TikTokMarkers { get; init; } = ["tiktok", "SIGI_STATE", "__UNIVERSAL_DATA_FOR_REHYDRATION__"];
    public IReadOnlyList<string> SuspiciousHeaders { get; init; } = ["x-proxy-error", "x-squid-error", "proxy-authenticate"];
}

public sealed record ScoreWeights
{
    public int Accessible { get; init; } = 45;
    public int Socks5 { get; init; } = 10;
    public int HttpConnect { get; init; } = 7;
    public int TlsValid { get; init; } = 15;
    public int LowLatency { get; init; } = 10;
    public int MultipleSourcesMax { get; init; } = 5;
    public int SecondSuccess { get; init; } = 10;
    public int ChallengePenalty { get; init; } = 30;
    public int LowLatencyMilliseconds { get; init; } = 300;
    public int ValidExitIp { get; init; } = 10;
    public int ExitIpDifferent { get; init; } = 5;
    public int PreferredCountry { get; init; } = 5;
    public int HomepagePassed { get; init; } = 15;
    public int MobilePagePassed { get; init; } = 10;
    public int VideoPagePassed { get; init; } = 10;
    public int OEmbedPassed { get; init; } = 5;
    public int BrowserPlaybackPassed { get; init; } = 25;
    public int StabilityPassed { get; init; } = 10;
    public int StableExitIp { get; init; } = 5;
    public int MediumLatency { get; init; } = 3;
    public int MediumLatencyMilliseconds { get; init; } = 800;
}

public sealed record RunSummary
{
    public int Sources { get; init; }
    public int SuccessfulSources { get; init; }
    public int SourceErrors { get; init; }
    public int FoundRows { get; init; }
    public int ValidCandidates { get; init; }
    public int UniqueEndpoints { get; init; }
    public IReadOnlyDictionary<string, int> Protocols { get; init; } = new Dictionary<string, int>();
    public int TikTokAccessible { get; init; }
    public int CaptchaOrChallenge { get; init; }
    public int Timeouts { get; init; }
    public double AverageLatencyMs { get; init; }
    public double MedianLatencyMs { get; init; }
    public TimeSpan Duration { get; init; }
}
