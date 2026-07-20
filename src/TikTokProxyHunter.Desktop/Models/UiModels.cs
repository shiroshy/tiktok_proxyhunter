using System.Collections.ObjectModel;
using System.Text.Json.Serialization;
using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Desktop.Models;

[JsonConverter(typeof(JsonStringEnumConverter<DesktopTheme>))]
public enum DesktopTheme { System, Dark, Light }

public enum ScanPreset { Quick, Normal, Deep, Custom }

public sealed record UiRunConfiguration
{
    public ScanPreset Preset { get; init; } = ScanPreset.Normal;
    public int MaximumCandidates { get; init; } = 3_000;
    public bool CheckPublicVideo { get; init; }
    public string PublicVideoUrl { get; init; } = string.Empty;
    public bool BrowserVerification { get; init; }
    public bool AllowUnknownGeo { get; init; } = true;
    public int Concurrency { get; init; } = 100;
    public int TimeoutSeconds { get; init; } = 5;
    public int StabilityAttempts { get; init; } = 3;
    public int BrowserLimit { get; init; } = 10;

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (MaximumCandidates is < 1 or > 250_000) errors.Add("Количество кандидатов должно быть от 1 до 250 000.");
        if (Concurrency is < 1 or > 500) errors.Add("Параллельность должна быть от 1 до 500.");
        if (TimeoutSeconds is < 1 or > 120) errors.Add("Тайм-аут должен быть от 1 до 120 секунд.");
        if (BrowserVerification && !CheckPublicVideo) errors.Add("Браузерная проверка требует проверки публичного видео.");
        if (CheckPublicVideo)
        {
            if (!Uri.TryCreate(PublicVideoUrl, UriKind.Absolute, out var url)
                || !Infrastructure.TikTokVideoUrlParser.TryParse(url, ["tiktok.com"], out _, out _, out _))
                errors.Add("Укажите публичную HTTPS-ссылку TikTok без query-параметров.");
        }
        return errors;
    }
}

public sealed record DesktopSettings
{
    public int SchemaVersion { get; init; } = 1;
    public DesktopTheme Theme { get; init; } = DesktopTheme.System;
    public string OutputDirectory { get; init; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "TikTokProxyHunter", "output");
    public string SourcesPath { get; init; } = "config/proxy-sources.json";
    public string LastPage { get; init; } = "Dashboard";
    public UiRunConfiguration QuickScan { get; init; } = new();
    public bool AutoOpenResults { get; init; } = true;
    public bool OnboardingCompleted { get; init; }
    public double? WindowLeft { get; init; }
    public double? WindowTop { get; init; }
    public double WindowWidth { get; init; } = 1360;
    public double WindowHeight { get; init; } = 820;
    public bool NavigationCompact { get; init; }
    public int BrowserTimeoutSeconds { get; init; } = 25;
    public bool CaptureScreenshotsOnFailure { get; init; }
    public bool RejectLikelyRussia { get; init; } = true;
    public GeoConfidenceLevel MinimumGeoConfidence { get; init; } = GeoConfidenceLevel.Medium;
    public string CountryDatabasePath { get; init; } = string.Empty;
    public string AsnDatabasePath { get; init; } = string.Empty;
    public IReadOnlyList<string> TestVideoUrls { get; init; } = [];
}

public sealed record UiRunState
{
    public HunterRunStatus Status { get; init; } = HunterRunStatus.Idle;
    public Guid? RunId { get; init; }
    public DateTimeOffset? StartedAt { get; init; }
    public HunterUiStage? CurrentStage { get; init; }
    public string StatusText { get; init; } = "Готово";
    public long Collected { get; init; }
    public long Unique { get; init; }
    public long ProtocolAlive { get; init; }
    public long GenericHttps { get; init; }
    public long TikTokAccessible { get; init; }
    public long Stable { get; init; }
    public long RejectedRussia { get; init; }
}

public sealed record PipelineStageItem
{
    public HunterUiStage Stage { get; init; }
    public string Name => StatusText.Stage(Stage);
    public HunterStageStatus Status { get; init; } = HunterStageStatus.Pending;
    public string StatusLabel => StatusText.StageStatus(Status);
    public long Processed { get; init; }
    public long? Total { get; init; }
    public long Passed { get; init; }
    public long Rejected { get; init; }
    public double ItemsPerSecond { get; init; }
    public bool IsIndeterminate => Status == HunterStageStatus.Running && Total is null;
}

public sealed record ProxyResultItem
{
    public required string Key { get; init; }
    public required string Address { get; init; }
    public required string ProxyUrl { get; init; }
    public required string Protocol { get; init; }
    public required string Country { get; init; }
    public string CountryCode { get; init; } = string.Empty;
    public string Asn { get; init; } = string.Empty;
    public string Sources { get; init; } = string.Empty;
    public required string TikTokStatus { get; init; }
    public required string VideoStatus { get; init; }
    public required string Stability { get; init; }
    public double LatencyMs { get; init; }
    public int Score { get; init; }
    public ProxyRecommendationClass RecommendationClass { get; init; }
    public string ClassLabel => StatusText.Recommendation(RecommendationClass);
    public DateTimeOffset LastChecked { get; init; }
    public bool IsFavorite { get; set; }
    public bool HasCredentials { get; init; }
    public ProxyCheckResult? Detail { get; init; }
    public string ProtocolLabel => Protocol;
    public string PlaybackStatus => VideoStatus;
    public string StabilityText => Stability;
    public string LatencyText => LatencyMs <= 0 ? "—" : $"{LatencyMs:N0} ms";
    public string SummaryLine => $"{Protocol} · {ClassLabel} · {Country}";
    public int SourceFamilyCount => Detail?.Endpoint.SourceFamilies.Count ?? 0;
    public string ExitIp => Detail?.ExitIp?.ExitIp ?? "Не подтверждён";
    public string GeoConfidence => StatusText.GeoConfidence(Detail?.Geo?.ConfidenceLevel ?? GeoConfidenceLevel.Unknown);

    public static ProxyResultItem From(ProxyCheckResult value)
    {
        var host = value.Endpoint.Host.Contains(':', StringComparison.Ordinal) ? $"[{value.Endpoint.Host}]" : value.Endpoint.Host;
        var scheme = value.Endpoint.DetectedProtocol switch
        { ProxyProtocol.Socks5 => "socks5", ProxyProtocol.Socks4 or ProxyProtocol.Socks4a => "socks4", _ => "http" };
        var page = value.TikTokCapabilities.LastOrDefault(x => x.Capability == TikTokCapability.TikTokHomepage);
        var playback = value.BrowserPlayback.OriginalPostPlaybackResult?.Status == BrowserVerificationStatus.Passed
            || value.BrowserPlayback.EmbedPlayerPlaybackResult?.Status == BrowserVerificationStatus.Passed;
        var stability = value.TikTokPageStability ?? value.Stability;
        var last = value.TikTokCapabilities.Select(x => x.CheckedAt)
            .Append(value.Probe?.CheckedAt ?? DateTimeOffset.MinValue)
            .Append(value.ExitIp?.CheckedAt ?? DateTimeOffset.MinValue)
            .Append(value.BrowserVerification?.CheckedAt ?? DateTimeOffset.MinValue).Max();
        return new()
        {
            Key = value.Endpoint.NormalizedKey, Address = $"{host}:{value.Endpoint.Port}", ProxyUrl = $"{scheme}://{host}:{value.Endpoint.Port}",
            Protocol = StatusText.Protocol(value.Endpoint.DetectedProtocol), Country = value.Geo?.CountryName ?? value.Geo?.CountryCode ?? "Не подтверждена",
            CountryCode = value.Geo?.CountryCode ?? string.Empty, Asn = value.Geo?.Asn ?? string.Empty,
            Sources = string.Join(", ", value.Endpoint.SourceFamilies), TikTokStatus = StatusText.Capability(page?.Status),
            VideoStatus = playback ? "Воспроизведение подтверждено" : StatusText.Playback(value.PlaybackCapability),
            Stability = stability is null ? "Не проверялась" : $"{stability.Attempts.Count(x => x.Success)}/{stability.Attempts.Count} · {StatusText.Stability(stability.Status)}",
            LatencyMs = stability?.MedianLatencyMs ?? value.Probe?.TunnelTime.TotalMilliseconds ?? 0, Score = value.Score.Value,
            RecommendationClass = value.RecommendationClass, LastChecked = last == DateTimeOffset.MinValue ? DateTimeOffset.UtcNow : last,
            HasCredentials = value.Endpoint.HasCredentials, Detail = value with
            { Endpoint = value.Endpoint with { Username = null, Password = null } }
        };
    }
}

public sealed record SourceHealthItem
{
    public required string Name { get; init; }
    public string Family { get; init; } = string.Empty;
    public string Protocol { get; init; } = string.Empty;
    public bool Enabled { get; init; }
    public ProxySourceHealthStatus Status { get; init; }
    public string StatusLabel => StatusText.SourceHealth(Status);
    public int Candidates { get; init; }
    public int Valid { get; init; }
    public double LatencyMs { get; init; }
    public DateTimeOffset? LastSuccess { get; init; }
    public string License { get; init; } = string.Empty;
    public string Homepage { get; init; } = string.Empty;
    public string? Reason { get; init; }
}

public sealed record RunHistoryItem
{
    public required string Directory { get; init; }
    public required HunterRunManifest Manifest { get; init; }
    public DateTimeOffset StartedAt => Manifest.Summary.StartedAt;
    public HunterRunSummary Summary => Manifest.Summary;
    public string Status => StatusText.RunStatus(Manifest.Summary.Status);
    public string StatusLabel => Status;
    public bool CanResume => Manifest.Summary.Status is HunterRunStatus.Cancelled or HunterRunStatus.Failed
        && File.Exists(Path.Combine(Directory, "run-checkpoint.json")) && File.Exists(Path.Combine(Directory, "run-state.private.json"));
}

public sealed record UiErrorPresentation(string Title, string Reason, IReadOnlyList<string> Suggestions, string TechnicalDetails);

public sealed record RuntimeComponentState(string Name, bool Available, string Status, string? Detail = null);

public static class StatusText
{
    public static string CapabilityName(TikTokCapability value) => value switch
    {
        TikTokCapability.ShortGenericHttps => "Обычный HTTPS",
        TikTokCapability.TikTokHomepage => "Главная страница",
        TikTokCapability.TikTokMobilePage => "Мобильная страница (необязательно)",
        TikTokCapability.TikTokPostPage or TikTokCapability.TikTokPublicVideoPage => "Публичная публикация",
        TikTokCapability.TikTokOEmbed => "Официальный oEmbed",
        TikTokCapability.TikTokEmbedPlayer => "Официальный Embed Player",
        TikTokCapability.TikTokBrowserPlayback => "Воспроизведение в браузере",
        _ => "Дополнительная проверка"
    };
    public static string GeoConfidence(GeoConfidenceLevel value) => value switch
    {
        GeoConfidenceLevel.Verified => "Проверена", GeoConfidenceLevel.High => "Высокая",
        GeoConfidenceLevel.Medium => "Средняя", GeoConfidenceLevel.Low => "Низкая",
        GeoConfidenceLevel.Conflicting => "Противоречивая", _ => "Неизвестная"
    };
    public static string Recommendation(ProxyRecommendationClass value) => value switch
    {
        ProxyRecommendationClass.Recommended => "Рекомендован",
        ProxyRecommendationClass.FullPlaybackVerified => "Воспроизведение подтверждено",
        ProxyRecommendationClass.EmbedPlaybackVerified => "Embed-видео воспроизводится",
        ProxyRecommendationClass.StablePageAccess => "Стабильно открывает TikTok",
        ProxyRecommendationClass.PostPageAccessible => "Открывает публикацию TikTok",
        ProxyRecommendationClass.EmbedPlayerAccessible => "Открывает Embed Player",
        ProxyRecommendationClass.PageOnly or ProxyRecommendationClass.VideoPageAccessible => "Открывает страницу TikTok",
        ProxyRecommendationClass.TikTokAccessibleGeoUnknown => "Страна не подтверждена",
        ProxyRecommendationClass.ProtocolOnly => "Работает только протокол",
        _ => "Отклонён"
    };
    public static string Capability(TikTokCapabilityStatus? value) => value switch
    {
        TikTokCapabilityStatus.Passed => "Пройдено", TikTokCapabilityStatus.Failed => "Не пройдено",
        TikTokCapabilityStatus.Unavailable => "Недоступно", TikTokCapabilityStatus.Skipped => "Не проверялось",
        TikTokCapabilityStatus.NotConfigured => "Не настроено", TikTokCapabilityStatus.Blocked => "Заблокировано",
        TikTokCapabilityStatus.Challenge => "CAPTCHA", TikTokCapabilityStatus.Timeout => "Тайм-аут",
        TikTokCapabilityStatus.RateLimited => "Ограничено сервисом", TikTokCapabilityStatus.Unsupported => "Не поддерживается",
        TikTokCapabilityStatus.InvalidContent => "Неверное содержимое", _ => "Не проверялось"
    };
    public static string Playback(PlaybackCapability value) => value switch
    { PlaybackCapability.FullPlaybackVerified => "Воспроизведение подтверждено", PlaybackCapability.EmbedPlaybackVerified => "Embed воспроизводится",
      PlaybackCapability.EmbedPlayerAccessible => "Player доступен", PlaybackCapability.NotConfigured => "Не настроено", _ => "Не проверялось" };
    public static string Stability(ProxyStabilityStatus value) => value switch
    { ProxyStabilityStatus.Stable => "стабильно", ProxyStabilityStatus.Intermittent => "с перебоями",
      ProxyStabilityStatus.Unstable => "нестабильно", ProxyStabilityStatus.Dead => "не работает", _ => "недостаточно данных" };
    public static string Protocol(ProxyProtocol value) => value switch
    { ProxyProtocol.HttpsConnect => "HTTP CONNECT", ProxyProtocol.Http => "HTTP", ProxyProtocol.Socks5 => "SOCKS5",
      ProxyProtocol.Socks4 => "SOCKS4", ProxyProtocol.Socks4a => "SOCKS4a", _ => "Не определён" };
    public static string Stage(HunterUiStage value) => value switch
    { HunterUiStage.Preparing => "Подготовка", HunterUiStage.LoadingSources => "Загрузка источников",
      HunterUiStage.Normalizing => "Нормализация", HunterUiStage.ProbingProtocols => "Проверка протоколов",
      HunterUiStage.CheckingHttps => "Проверка HTTPS", HunterUiStage.CheckingTikTok => "Проверка TikTok",
      HunterUiStage.ResolvingExitIp => "Определение выходного IP", HunterUiStage.ResolvingGeo => "Определение страны",
      HunterUiStage.CheckingStability => "Проверка стабильности", HunterUiStage.CheckingVideo => "Проверка видео",
      HunterUiStage.CheckingBrowser => "Проверка воспроизведения", HunterUiStage.Exporting => "Экспорт", _ => value.ToString() };
    public static string StageStatus(HunterStageStatus value) => value switch
    { HunterStageStatus.Pending => "Ожидает", HunterStageStatus.Running => "Выполняется", HunterStageStatus.Completed => "Готово",
      HunterStageStatus.CompletedWithWarnings => "Готово с предупреждениями", HunterStageStatus.Failed => "Ошибка",
      HunterStageStatus.Skipped => "Пропущено", HunterStageStatus.Cancelled => "Отменено", _ => value.ToString() };
    public static string RunStatus(HunterRunStatus value) => value switch
    { HunterRunStatus.Idle => "Готово", HunterRunStatus.Preparing => "Подготовка", HunterRunStatus.Running => "Выполняется",
      HunterRunStatus.Cancelling => "Остановка", HunterRunStatus.Cancelled => "Остановлено пользователем",
      HunterRunStatus.Failed => "Ошибка", HunterRunStatus.Completed => "Завершено", _ => value.ToString() };
    public static string SourceHealth(ProxySourceHealthStatus value) => value switch
    { ProxySourceHealthStatus.Healthy => "Работает", ProxySourceHealthStatus.Degraded => "Есть предупреждения",
      ProxySourceHealthStatus.Unavailable => "Недоступен", ProxySourceHealthStatus.Disabled => "Отключён",
      ProxySourceHealthStatus.RateLimited => "Ограничен", ProxySourceHealthStatus.Captcha => "CAPTCHA", _ => value.ToString() };
}

public static class ProxyResultQuery
{
    public static IEnumerable<ProxyResultItem> Apply(IEnumerable<ProxyResultItem> source, string? classFilter,
        string? protocolFilter, string? country, string? search, double maximumLatency, bool credentialsFreeOnly)
    {
        var query = source;
        if (!string.IsNullOrWhiteSpace(classFilter) && !classFilter.Equals("Все", StringComparison.OrdinalIgnoreCase))
            query = query.Where(x => x.RecommendationClass.ToString().Equals(classFilter, StringComparison.OrdinalIgnoreCase)
                || classFilter.Equals("GeoUnknown", StringComparison.OrdinalIgnoreCase) && x.RecommendationClass == ProxyRecommendationClass.TikTokAccessibleGeoUnknown);
        if (!string.IsNullOrWhiteSpace(protocolFilter) && !protocolFilter.Equals("Все", StringComparison.OrdinalIgnoreCase))
            query = query.Where(x => x.Protocol.Equals(protocolFilter, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(country)) query = query.Where(x => x.CountryCode.Equals(country, StringComparison.OrdinalIgnoreCase));
        if (maximumLatency > 0) query = query.Where(x => x.LatencyMs <= maximumLatency);
        if (credentialsFreeOnly) query = query.Where(x => !x.HasCredentials);
        if (!string.IsNullOrWhiteSpace(search)) query = query.Where(x =>
            new[] { x.Address, x.Country, x.CountryCode, x.Asn, x.Sources }.Any(v => v.Contains(search, StringComparison.OrdinalIgnoreCase)));
        return query.OrderByDescending(x => QualityRank(x.RecommendationClass)).ThenByDescending(x => x.Score)
            .ThenBy(x => x.LatencyMs).ThenBy(x => x.Address, StringComparer.OrdinalIgnoreCase);
    }
    public static int QualityRank(ProxyRecommendationClass value) => value switch
    { ProxyRecommendationClass.Recommended => 9, ProxyRecommendationClass.FullPlaybackVerified => 8,
      ProxyRecommendationClass.EmbedPlaybackVerified => 7, ProxyRecommendationClass.EmbedPlayerAccessible => 6,
      ProxyRecommendationClass.PostPageAccessible => 5, ProxyRecommendationClass.StablePageAccess => 4,
      ProxyRecommendationClass.PageOnly => 3, ProxyRecommendationClass.TikTokAccessibleGeoUnknown => 2,
      ProxyRecommendationClass.ProtocolOnly => 1, _ => 0 };
}
