using System.Text.Json.Serialization;

namespace TikTokProxyHunter.Core;

[JsonConverter(typeof(JsonStringEnumConverter<ProxySourceHealthStatus>))]
public enum ProxySourceHealthStatus
{
    Healthy, Degraded, Empty, InvalidFormat, RateLimited, AuthenticationRequired,
    Captcha, Unavailable, Oversized, SuspiciousContent, Disabled
}

public sealed record ProxySourceHealth
{
    public required string SourceName { get; init; }
    public string? SourceFamily { get; init; }
    public ProxySourceHealthStatus Status { get; init; }
    public int? HttpStatus { get; init; }
    public string? ContentType { get; init; }
    public long ContentBytes { get; init; }
    public TimeSpan DownloadTime { get; init; }
    public int ExtractedRows { get; init; }
    public int ValidCandidates { get; init; }
    public double ValidPercentage { get; init; }
    public string? ContentSha256 { get; init; }
    public DateTimeOffset? LastSuccess { get; init; }
    public int ConsecutiveFailures { get; init; }
    public string? DuplicateOf { get; init; }
    public string? Reason { get; init; }
    public bool FromCache { get; init; }
}

[JsonConverter(typeof(JsonStringEnumConverter<SourceDiscoveryStatus>))]
public enum SourceDiscoveryStatus { Candidate, AcceptedForReview, Duplicate, Rejected, Suspicious, Unavailable }

public sealed record DiscoveredProxySource
{
    public required ProxySourceDefinition Definition { get; init; }
    public SourceDiscoveryStatus Status { get; init; }
    public required string Reason { get; init; }
    public string Repository { get; init; } = string.Empty;
    public DateTimeOffset? RepositoryUpdatedAt { get; init; }
    public string? Fingerprint { get; init; }
    public int ValidCandidates { get; init; }
}

public sealed record SourceDiscoveryReport
{
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public int GitHubRateLimitRemaining { get; init; }
    public DateTimeOffset? GitHubRateLimitReset { get; init; }
    public IReadOnlyList<DiscoveredProxySource> Sources { get; init; } = [];
    public string? StopReason { get; init; }
}

[JsonConverter(typeof(JsonStringEnumConverter<ExitIpStatus>))]
public enum ExitIpStatus { Resolved, ConsensusMismatch, SameAsDirectIp, ProviderBlocked, Timeout, InvalidResponse, Unavailable }

public sealed record ExitIpProvider
{
    public required string Name { get; init; }
    public required string Url { get; init; }
    public string? JsonField { get; init; }
    public bool Enabled { get; init; } = true;
    public int TimeoutSeconds { get; init; } = 8;
    public string Family { get; init; } = string.Empty;
    public string? HttpUrl { get; init; }
    public string ParserType { get; init; } = "auto";
    public string? ExpectedContentType { get; init; }
    public int Priority { get; init; } = 50;
    public double TrustWeight { get; init; } = 0.5;
    public bool SupportsIpv4 { get; init; } = true;
    public bool SupportsIpv6 { get; init; } = true;
}

public sealed record ExitIpProviderResult(string Provider, ExitIpStatus Status, string? IpAddress, TimeSpan Duration, string? Reason = null);

public sealed record ExitIpResolutionResult
{
    public ExitIpStatus Status { get; init; }
    public string? ExitIp { get; init; }
    public string? DirectIp { get; init; }
    public bool IsTransparentOrIneffective { get; init; }
    public double Confidence { get; init; }
    public IReadOnlyList<ExitIpProviderResult> Providers { get; init; } = [];
    public IReadOnlyList<ExitIpResolutionAttempt> Attempts { get; init; } = [];
    public ExitIpResolutionConfidence ResolutionConfidence { get; init; } = ExitIpResolutionConfidence.None;
    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;
}

[JsonConverter(typeof(JsonStringEnumConverter<ExitIpResolutionMethod>))]
public enum ExitIpResolutionMethod { ExternalHttpsProvider, ExternalHttpProvider, CustomEchoEndpoint, ObservedSocketPeer, BrowserEchoEndpoint }

[JsonConverter(typeof(JsonStringEnumConverter<ExitIpProviderHealthStatus>))]
public enum ExitIpProviderHealthStatus { Healthy, Degraded, RateLimited, TemporarilyDisabled, Unavailable, InvalidResponse }

[JsonConverter(typeof(JsonStringEnumConverter<ExitIpResolutionConfidence>))]
public enum ExitIpResolutionConfidence { None, SingleProvider, Consensus, High }

public sealed record ExitIpResolutionAttempt
{
    public required string Provider { get; init; }
    public string ProviderFamily { get; init; } = string.Empty;
    public ExitIpResolutionMethod Method { get; init; }
    public ExitIpStatus Status { get; init; }
    public string? IpAddress { get; init; }
    public int? HttpStatus { get; init; }
    public TimeSpan Duration { get; init; }
    public string? ContentType { get; init; }
    public string? Reason { get; init; }
    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;
}

public sealed record ExitIpProviderHealth
{
    public required string Provider { get; init; }
    public ExitIpProviderHealthStatus Status { get; init; }
    public int Successes { get; init; }
    public int ConsecutiveFailures { get; init; }
    public int RateLimitResponses { get; init; }
    public DateTimeOffset? CooldownUntil { get; init; }
    public string? LastError { get; init; }
}

[JsonConverter(typeof(JsonStringEnumConverter<ProxyGeoStatus>))]
public enum ProxyGeoStatus { Resolved, GeoUncertain, ProviderBlocked, Timeout, InvalidResponse, Unavailable }

public sealed record GeoProvider
{
    public required string Name { get; init; }
    public required string UrlTemplate { get; init; }
    public bool Enabled { get; init; } = true;
    public int TimeoutSeconds { get; init; } = 8;
    public double TrustWeight { get; init; } = 0.5;
}

public sealed record ProxyGeoInfo
{
    public ProxyGeoStatus Status { get; init; }
    public required string IpAddress { get; init; }
    public string? CountryCode { get; init; }
    public string? CountryName { get; init; }
    public string? Region { get; init; }
    public string? City { get; init; }
    public string? Asn { get; init; }
    public string? Organization { get; init; }
    public bool? IsHosting { get; init; }
    public string? Timezone { get; init; }
    public IReadOnlyList<string> Sources { get; init; } = [];
    public double Confidence { get; init; }
    public GeoResolutionDecision Decision { get; init; } = GeoResolutionDecision.Unknown;
    public GeoConfidenceLevel ConfidenceLevel { get; init; } = GeoConfidenceLevel.Unknown;
    public GeoRiskClassification Risk { get; init; } = GeoRiskClassification.Unverified;
    public IReadOnlyList<GeoEvidence> Evidence { get; init; } = [];
    public IReadOnlyDictionary<GeoEvidenceField, GeoFieldResolution> FieldResolutions { get; init; } =
        new Dictionary<GeoEvidenceField, GeoFieldResolution>();
    public DateTimeOffset ResolvedAt { get; init; } = DateTimeOffset.UtcNow;
}

[JsonConverter(typeof(JsonStringEnumConverter<GeoEvidenceField>))]
public enum GeoEvidenceField { CountryCode, Asn, Organization, NetworkPrefix, Hosting, Region, City }

[JsonConverter(typeof(JsonStringEnumConverter<GeoConfidenceLevel>))]
public enum GeoConfidenceLevel { Verified, High, Medium, Low, Unknown, Conflicting }

[JsonConverter(typeof(JsonStringEnumConverter<GeoResolutionDecision>))]
public enum GeoResolutionDecision { ConfirmedRussia, LikelyRussia, ConfirmedNonRussia, LikelyNonRussia, Unknown, Conflicting }

[JsonConverter(typeof(JsonStringEnumConverter<GeoRiskClassification>))]
public enum GeoRiskClassification { RejectedRussia, NonRussian, Unverified, Conflicting }

public sealed record GeoEvidence
{
    public required string Provider { get; init; }
    public string? CountryCode { get; init; }
    public string? Asn { get; init; }
    public string? Organization { get; init; }
    public string? NetworkPrefix { get; init; }
    public bool? IsHosting { get; init; }
    public double RawConfidence { get; init; }
    public double TrustWeight { get; init; } = 0.5;
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public TimeSpan? ResponseAge { get; init; }
    public bool IsError { get; init; }
    public bool IsRateLimited { get; init; }
    public string? Error { get; init; }
}

public sealed record GeoFieldResolution
{
    public GeoEvidenceField Field { get; init; }
    public string? Value { get; init; }
    public GeoConfidenceLevel Confidence { get; init; }
    public IReadOnlyList<string> Providers { get; init; } = [];
}

[JsonConverter(typeof(JsonStringEnumConverter<TikTokCapability>))]
public enum TikTokCapability
{
    TikTokDnsAndTunnel, TikTokHomepage, TikTokMobilePage, TikTokOEmbed,
    TikTokPublicVideoPage, TikTokBrowserPlayback, ShortGenericHttps,
    TikTokPostPage, TikTokEmbedPlayer, TikTokOriginalPostPlayback, TikTokEmbedPlayerPlayback
}

[JsonConverter(typeof(JsonStringEnumConverter<TikTokCapabilityStatus>))]
public enum TikTokCapabilityStatus
{
    Passed, Failed, Skipped, Unavailable, Challenge, Blocked, RateLimited, InvalidContent,
    MediaUnverified, Timeout, Unsupported, NotConfigured
}

public sealed record TikTokCapabilityResult
{
    public TikTokCapability Capability { get; init; }
    public TikTokCapabilityStatus Status { get; init; }
    public Uri? Url { get; init; }
    public TimeSpan Duration { get; init; }
    public int? HttpStatus { get; init; }
    public string? Reason { get; init; }
    public int Attempts { get; init; } = 1;
    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;
}

[JsonConverter(typeof(JsonStringEnumConverter<TechnicalTikTokAccess>))]
public enum TechnicalTikTokAccess { None, Accessible, AccessibleGeoUnknown, Blocked, Challenge, Unavailable }

[JsonConverter(typeof(JsonStringEnumConverter<PlaybackCapability>))]
public enum PlaybackCapability { None, EmbedPlayerAccessible, EmbedPlaybackVerified, FullPlaybackVerified, NotConfigured }

[JsonConverter(typeof(JsonStringEnumConverter<RecommendationEligibility>))]
public enum RecommendationEligibility
{
    Eligible, NoTechnicalAccess, ExitIpUnresolved, GeoInsufficient, RussianExit, Unstable,
    PlaybackUnverified, ChallengeDetected, CredentialsPresent, LatencyTooHigh
}

[JsonConverter(typeof(JsonStringEnumConverter<ProxyStabilityStatus>))]
public enum ProxyStabilityStatus { Stable, Unstable, Intermittent, Dead, NotEnoughData }

public sealed record ProxyCheckAttempt
{
    public int Attempt { get; init; }
    public bool Success { get; init; }
    public TimeSpan Latency { get; init; }
    public string? ExitIp { get; init; }
    public TikTokCapabilityStatus Status { get; init; }
    public string? Error { get; init; }
    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;
}

public sealed record ProxyStabilityResult
{
    public ProxyStabilityStatus Status { get; init; }
    public IReadOnlyList<ProxyCheckAttempt> Attempts { get; init; } = [];
    public double SuccessRatio { get; init; }
    public double MedianLatencyMs { get; init; }
    public double JitterMs { get; init; }
    public bool StableExitIp { get; init; }
    public string? FailureSequence { get; init; }
    public TikTokCapability Capability { get; init; } = TikTokCapability.TikTokHomepage;
    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;
}

[JsonConverter(typeof(JsonStringEnumConverter<StabilityKind>))]
public enum StabilityKind { NetworkStability, TikTokPageStability, PlaybackStability }

[JsonConverter(typeof(JsonStringEnumConverter<BrowserVerificationStatus>))]
public enum BrowserVerificationStatus
{
    Passed, Failed, Skipped, Unavailable, Challenge, Blocked, MediaUnverified,
    TlsFailure, WrongDomain, Timeout, Unsupported, NotConfigured
}

[JsonConverter(typeof(JsonStringEnumConverter<BrowserVerificationMode>))]
public enum BrowserVerificationMode { OriginalPostPage, OfficialEmbedPlayer }

[JsonConverter(typeof(JsonStringEnumConverter<MediaRequestCategory>))]
public enum MediaRequestCategory { TikTokDocument, TikTokApi, TikTokPlayer, TikTokMedia, TikTokImage, ThirdPartyAnalytics, Challenge, Unknown }

public sealed record MediaRequestObservation
{
    public required string Host { get; init; }
    public required string PathPattern { get; init; }
    public MediaRequestCategory Category { get; init; }
    public int Status { get; init; }
    public string? ContentType { get; init; }
    public string? ResourceType { get; init; }
    public bool ByteRange { get; init; }
    public long? ContentLength { get; init; }
}

public sealed record BrowserVerificationResult
{
    public BrowserVerificationStatus Status { get; init; }
    public Uri? Url { get; init; }
    public bool VideoElementFound { get; init; }
    public int? ReadyState { get; init; }
    public int? NetworkState { get; init; }
    public double? DurationSeconds { get; init; }
    public double PlaybackProgressSeconds { get; init; }
    public bool MediaError { get; init; }
    public int SuccessfulMediaResponses { get; init; }
    public int VideoElementCount { get; init; }
    public double? InitialCurrentTimeSeconds { get; init; }
    public double? FinalCurrentTimeSeconds { get; init; }
    public int? NavigationStatus { get; init; }
    public Uri? FinalUrl { get; init; }
    public bool ChallengeDetected { get; init; }
    public IReadOnlyList<string> MediaCdnHosts { get; init; } = [];
    public IReadOnlyList<string> ConsoleErrors { get; init; } = [];
    public IReadOnlyList<string> PageErrors { get; init; } = [];
    public TimeSpan Elapsed { get; init; }
    public string? ScreenshotPath { get; init; }
    public string? Reason { get; init; }
    public BrowserVerificationMode Mode { get; init; } = BrowserVerificationMode.OriginalPostPage;
    public bool ExpectedPlayerSurfaceFound { get; init; }
    public IReadOnlyList<MediaRequestObservation> MediaObservations { get; init; } = [];
    public IReadOnlyList<string> PlayerEvents { get; init; } = [];
    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;
}

public sealed record BrowserPlaybackSet
{
    public BrowserVerificationResult? OriginalPostPlaybackResult { get; init; }
    public BrowserVerificationResult? EmbedPlayerPlaybackResult { get; init; }
}

[JsonConverter(typeof(JsonStringEnumConverter<ProxyRecommendationClass>))]
public enum ProxyRecommendationClass
{
    Rejected, ProtocolOnly, TikTokAccessibleGeoUnknown, PageOnly, StablePageAccess,
    PostPageAccessible, EmbedPlayerAccessible, EmbedPlaybackVerified, FullPlaybackVerified,
    Recommended, VideoPageAccessible, PlaybackVerified
}

public sealed record GeoOptions
{
    public bool Enabled { get; init; } = true;
    public IReadOnlyList<string> RejectCountryCodes { get; init; } = ["RU"];
    public IReadOnlyList<string> PreferredCountryCodes { get; init; } = ["KZ", "FI", "EE", "LV", "LT", "PL", "DE", "NL", "GE", "TR"];
    public int MinimumConsensusProviders { get; init; } = 2;
    public bool AllowUnknownCountry { get; init; }
    public IReadOnlyList<string> RejectConfirmedCountryCodes { get; init; } = ["RU"];
    public IReadOnlyList<string> RejectLikelyCountryCodes { get; init; } = ["RU"];
    public bool AllowUnknownCountryForFastCheck { get; init; } = true;
    public bool AllowConflictingCountryForFastCheck { get; init; } = true;
    public bool AllowUnknownCountryForBrowserCheck { get; init; } = true;
    public bool AllowConflictingCountryForBrowserCheck { get; init; } = true;
    public bool AllowUnknownCountryForRecommendation { get; init; }
    public GeoConfidenceLevel MinimumConfidenceForRecommendation { get; init; } = GeoConfidenceLevel.Medium;
    public int UnknownCountryScorePenalty { get; init; } = 15;
    public int ConflictingCountryScorePenalty { get; init; } = 25;
    public LocalGeoDatabaseOptions LocalDatabase { get; init; } = new();
    public IReadOnlyList<GeoProvider> Providers { get; init; } = [];
}

public sealed record LocalGeoDatabaseOptions
{
    public bool Enabled { get; init; }
    public string CountryDatabasePath { get; init; } = string.Empty;
    public string AsnDatabasePath { get; init; } = string.Empty;
    public double TrustWeight { get; init; } = 1.0;
}

public sealed record ExitIpOptions
{
    public int MinimumConsensusProviders { get; init; } = 2;
    public IReadOnlyList<ExitIpProvider> Providers { get; init; } = [];
    public IReadOnlyList<string> CustomEchoEndpoints { get; init; } = [];
    public int MaximumAttemptsPerProxy { get; init; } = 5;
    public int CircuitBreakerFailureThreshold { get; init; } = 5;
    public int RateLimitCooldownSeconds { get; init; } = 120;
}

public sealed record TikTokMobilePageOptions
{
    public bool Enabled { get; init; } = true;
    public bool RequiredForTechnicalAccess { get; init; }
    public bool RequiredForRecommendation { get; init; }
    public int ScoreBonus { get; init; } = 2;
    public int FailurePenalty { get; init; }
}

public sealed record TikTokVerificationOptions
{
    public IReadOnlyList<string> PublicVideoTestUrls { get; init; } = [];
    public bool RequirePublicVideoUrlForPlaybackTest { get; init; } = true;
    public string OEmbedEndpoint { get; init; } = "https://www.tiktok.com/oembed";
    public int MinimumSuccessfulVideoUrls { get; init; } = 1;
    public int MaximumVideoUrlsPerProxy { get; init; } = 2;
    public IReadOnlyList<string> AllowedVideoDomains { get; init; } = ["tiktok.com"];
    public TikTokMobilePageOptions MobilePage { get; init; } = new();
    public IReadOnlyList<string> EmbedPlayerMarkers { get; init; } = ["x-tiktok-player", "player", "tiktok"];
    public int MaximumRecommendedLatencyMs { get; init; } = 2_000;
}

public sealed record StabilityOptions
{
    public int Attempts { get; init; } = 3;
    public int DelaySeconds { get; init; } = 10;
    public double MinimumSuccessRatio { get; init; } = 0.67;
    public double MaximumAllowedJitterMs { get; init; } = 1500;
    public IReadOnlyList<string> EligibleCapabilities { get; init; } = ["Homepage", "PublicPostPage", "EmbedPlayer", "BrowserPlayback"];
}

public sealed record ResultTtlOptions
{
    public int ProtocolMinutes { get; init; } = 30;
    public int ExitIpMinutes { get; init; } = 20;
    public int GeoHours { get; init; } = 24;
    public int HomepageMinutes { get; init; } = 15;
    public int StabilityMinutes { get; init; } = 10;
    public int BrowserMinutes { get; init; } = 10;
}

public sealed record TikTokTestVideo
{
    public required string Name { get; init; }
    public required string Url { get; init; }
    public bool Enabled { get; init; } = true;
}

public sealed record TikTokVideoValidationResult
{
    public required string Name { get; init; }
    public Uri? PostUrl { get; init; }
    public string? PostId { get; init; }
    public Uri? PlayerUrl { get; init; }
    public TikTokCapabilityStatus Status { get; init; }
    public int? PlayerHttpStatus { get; init; }
    public int? OEmbedHttpStatus { get; init; }
    public bool Suitable { get; init; }
    public string? Reason { get; init; }
}

public sealed record TikTokEmbedPlayerResult
{
    public required string PostId { get; init; }
    public required Uri RequestedUrl { get; init; }
    public Uri? FinalUrl { get; init; }
    public TikTokCapabilityStatus Status { get; init; }
    public int? HttpStatus { get; init; }
    public TimeSpan Latency { get; init; }
    public bool ExpectedPlayerMarkersFound { get; init; }
    public bool ChallengeDetected { get; init; }
    public IReadOnlyList<MediaRequestObservation> MediaEndpointsObserved { get; init; } = [];
    public string? FailureReason { get; init; }
    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;
}

[JsonConverter(typeof(JsonStringEnumConverter<CapabilityNotRunReason>))]
public enum CapabilityNotRunReason { NotConfigured, NotEligible, LimitReached, DependencyUnavailable, ExpiredInput, BrowserUnavailable }

public sealed record CapabilityMatrix
{
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public IReadOnlyDictionary<string, long> Counts { get; init; } = new Dictionary<string, long>();
    public IReadOnlyDictionary<string, long> NotRunReasons { get; init; } = new Dictionary<string, long>();
}

public sealed record BrowserVerificationOptions
{
    public bool Enabled { get; init; }
    public int MinimumFastScore { get; init; } = 60;
    public int MaximumCandidates { get; init; } = 100;
    public int Concurrency { get; init; } = 2;
    public int NavigationTimeoutSeconds { get; init; } = 25;
    public int PlaybackObservationSeconds { get; init; } = 12;
    public double MinimumPlaybackProgressSeconds { get; init; } = 3;
    public IReadOnlyList<string> AllowedCdnDomains { get; init; } = [];
    public bool CaptureScreenshotOnFailure { get; init; }
    public string ScreenshotDirectory { get; init; } = "browser-failures";
}

public sealed record PipelineLimits
{
    public int MaximumProtocolChecks { get; init; } = 10_000;
    public int MaximumExitIpChecks { get; init; } = 3_000;
    public int MaximumFastTikTokChecks { get; init; } = 1_000;
    public int MaximumStabilityChecks { get; init; } = 200;
    public int MaximumVideoPageChecks { get; init; } = 100;
    public int MaximumBrowserChecks { get; init; } = 20;
}

public sealed record ProxyPreScoreWeights
{
    public int Socks5 { get; init; } = 20;
    public int HttpConnect { get; init; } = 15;
    public int Socks4a { get; init; } = 8;
    public int Socks4 { get; init; } = 5;
    public int Http { get; init; } = 3;
    public int LatencyBelow250 { get; init; } = 20;
    public int LatencyBelow500 { get; init; } = 15;
    public int LatencyBelow1000 { get; init; } = 8;
    public int LatencyBelow2000 { get; init; } = 3;
    public int IndependentSourceFamiliesMax { get; init; } = 15;
    public int ExitIpResolved { get; init; } = 15;
    public int ConfirmedNonRussia { get; init; } = 20;
    public int LikelyNonRussia { get; init; } = 10;
    public int ConflictingGeoPenalty { get; init; } = 10;
}

public sealed record ProxyPreScore(int Value, bool Rejected, IReadOnlyList<string> Reasons);

[JsonConverter(typeof(JsonStringEnumConverter<PipelineStage>))]
public enum PipelineStage
{
    Collected, Normalized, ProtocolAlive, ShortHttpsPassed, ExitIpResolved, GeoEvaluated, FastTikTokEligible,
    TikTokHomepagePassed, TikTokMobilePassed, StabilityPassed, PublicVideoPassed,
    BrowserEligible, PlaybackVerified, Recommended
}

public sealed record PipelineStageStatistics
{
    public PipelineStage Stage { get; init; }
    public long InputCount { get; init; }
    public long PassedCount { get; init; }
    public long RejectedCount { get; init; }
    public IReadOnlyDictionary<string, long> RejectionReasons { get; init; } = new Dictionary<string, long>();
    public TimeSpan Elapsed { get; init; }
    public double AverageLatencyMs { get; init; }
    public double MedianLatencyMs { get; init; }
    public IReadOnlyList<KeyValuePair<string, long>> TopFailureCategories { get; init; } = [];
}

public sealed record PipelineFunnel
{
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public IReadOnlyList<PipelineStageStatistics> Stages { get; init; } = [];
}

public sealed record GeoDatabaseValidationResult
{
    public bool Success { get; init; }
    public string DatabaseType { get; init; } = string.Empty;
    public string Path { get; init; } = string.Empty;
    public bool Exists { get; init; }
    public bool FormatValid { get; init; }
    public DateTimeOffset? LastModified { get; init; }
    public TimeSpan? Age { get; init; }
    public int SuccessfulTestLookups { get; init; }
    public string? Reason { get; init; }
}

public sealed record BrowserDoctorResult
{
    public bool PackageAvailable { get; init; }
    public bool ChromiumInstalled { get; init; }
    public bool LaunchSucceeded { get; init; }
    public bool CleanShutdown { get; init; }
    public bool HttpProxyConfigurationSupported { get; init; }
    public bool Socks5ProxyConfigurationSupported { get; init; }
    public bool LocalIntegrationTestAvailable { get; init; }
    public string InstallCommand { get; init; } = string.Empty;
    public string? Reason { get; init; }
}

public sealed record GitHubDiscoveryOptions
{
    public int MaximumRepositories { get; init; } = 25;
    public int MaximumFilesPerRepository { get; init; } = 8;
    public int MaximumSampleBytes { get; init; } = 1_048_576;
    public int MinimumCandidates { get; init; } = 10;
    public int MinimumRateLimitRemaining { get; init; } = 2;
    public int MaximumRepositoryAgeDays { get; init; } = 180;
}

public sealed record RunCheckpoint
{
    public required string ConfigurationHash { get; init; }
    public DateTimeOffset UpdatedAt { get; init; } = DateTimeOffset.UtcNow;
    public string Stage { get; init; } = string.Empty;
    public HashSet<string> CompletedEndpointKeys { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> ProbedEndpointKeys { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}
