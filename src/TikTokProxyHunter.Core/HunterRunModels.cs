using System.Text.Json.Serialization;

namespace TikTokProxyHunter.Core;

[JsonConverter(typeof(JsonStringEnumConverter<HunterRunStatus>))]
public enum HunterRunStatus { Idle, Preparing, Running, Cancelling, Cancelled, Failed, Completed }

[JsonConverter(typeof(JsonStringEnumConverter<HunterProgressEvent>))]
public enum HunterProgressEvent
{
    RunStarted, StageStarted, StageProgress, CandidateUpdated, ProxyResultUpdated,
    StageCompleted, RunPaused, RunResumed, RunCancelled, RunFailed, RunCompleted, LogReceived
}

[JsonConverter(typeof(JsonStringEnumConverter<HunterUiStage>))]
public enum HunterUiStage
{
    Preparing, LoadingSources, Normalizing, ProbingProtocols, CheckingHttps, CheckingTikTok,
    ResolvingExitIp, ResolvingGeo, CheckingStability, CheckingVideo, CheckingBrowser, Exporting
}

[JsonConverter(typeof(JsonStringEnumConverter<HunterStageStatus>))]
public enum HunterStageStatus { Pending, Running, Completed, CompletedWithWarnings, Failed, Skipped, Cancelled }

public sealed record HunterRunConfiguration
{
    public string SourcesPath { get; init; } = "config/proxy-sources.json";
    public required string OutputDirectory { get; init; }
    public int MaximumCandidates { get; init; } = 3_000;
    public int Concurrency { get; init; } = 100;
    public int TimeoutSeconds { get; init; } = 5;
    public bool AllowUnknownGeoForTechnicalCheck { get; init; } = true;
    public bool AllowConflictingGeoForTechnicalCheck { get; init; } = true;
    public bool RejectLikelyRussia { get; init; } = true;
    public GeoConfidenceLevel MinimumGeoConfidenceForRecommendation { get; init; } = GeoConfidenceLevel.Medium;
    public IReadOnlyList<Uri> PublicVideoUrls { get; init; } = [];
    public bool BrowserVerificationEnabled { get; init; }
    public int BrowserLimit { get; init; } = 10;
    public int StabilityAttempts { get; init; } = 3;
    public bool Resume { get; init; }
    public string? ResumeRunDirectory { get; init; }
}

public sealed record HunterStageProgress
{
    public HunterUiStage Stage { get; init; }
    public HunterStageStatus Status { get; init; }
    public long Processed { get; init; }
    public long? Total { get; init; }
    public long Passed { get; init; }
    public long Rejected { get; init; }
    public double ItemsPerSecond { get; init; }
    public TimeSpan Elapsed { get; init; }
    public IReadOnlyDictionary<string, long> FailureCategories { get; init; } = new Dictionary<string, long>();
}

public sealed record HunterRunProgress
{
    public Guid RunId { get; init; }
    public HunterProgressEvent Event { get; init; }
    public HunterRunStatus Status { get; init; }
    public HunterStageProgress? Stage { get; init; }
    public string? Message { get; init; }
    public ProxyCheckResult? ProxyResult { get; init; }
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
}

public sealed record HunterRunFailure
{
    public required string UserMessage { get; init; }
    public required string TechnicalType { get; init; }
    public string? TechnicalMessage { get; init; }
    public HunterUiStage? Stage { get; init; }
}

public sealed record HunterRunSummary
{
    public Guid RunId { get; init; }
    public HunterRunStatus Status { get; init; }
    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset FinishedAt { get; init; }
    public string OutputDirectory { get; init; } = string.Empty;
    public long Collected { get; init; }
    public long Unique { get; init; }
    public long ProtocolAlive { get; init; }
    public long GenericHttpsPassed { get; init; }
    public long TikTokAccessible { get; init; }
    public long Stable { get; init; }
    public long PlaybackVerified { get; init; }
    public long Recommended { get; init; }
    public long RejectedRussia { get; init; }
    public HunterRunFailure? Failure { get; init; }
}

public sealed record HunterRunManifest
{
    public int SchemaVersion { get; init; } = 1;
    public Guid RunId { get; init; }
    public required HunterRunConfiguration Configuration { get; init; }
    public required HunterRunSummary Summary { get; init; }
    public string ConfigurationHash { get; init; } = string.Empty;
    public string AppVersion { get; init; } = string.Empty;
}

public sealed record HunterRunResult
{
    public required HunterRunSummary Summary { get; init; }
    public IReadOnlyList<ProxyCheckResult> Results { get; init; } = [];
    public IReadOnlyList<ProxySourceHealth> SourceHealth { get; init; } = [];
}
