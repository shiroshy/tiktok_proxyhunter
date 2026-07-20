using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Desktop.Models;
using TikTokProxyHunter.Desktop.Services;
using TikTokProxyHunter.Infrastructure;

namespace TikTokProxyHunter.Desktop.ViewModels;

public sealed partial class ProxyDetailsViewModel(IClipboardService clipboard, INavigationService navigation, GeoOptions geoOptions) : ObservableObject
{
    [ObservableProperty] private ProxyResultItem? result;
    [ObservableProperty] private string explanation = "Выберите прокси в результатах.";
    public IAsyncRelayCommand CopyCommand => new AsyncRelayCommand(async () => { if (Result is not null) await clipboard.CopyProxyUrlAsync(Result); }, () => Result is not null);
    public IRelayCommand BackCommand => new RelayCommand(() => navigation.Navigate("Results"));
    public void SetResult(ProxyResultItem item)
    {
        Result = item; Explanation = item.Detail is null ? "Подробные результаты недоступны."
            : FormatFriendlyExplanation(item.Detail); OnPropertyChanged(nameof(Capabilities)); OnPropertyChanged(nameof(GeoEvidence));
    }
    public IReadOnlyList<CapabilityDisplayItem> Capabilities => Result?.Detail?.TikTokCapabilities.Select(x => new CapabilityDisplayItem(
        StatusText.CapabilityName(x.Capability), StatusText.Capability(x.Status), x.Duration.TotalMilliseconds,
        FriendlyReason(x))).ToArray() ?? [];
    public IReadOnlyList<GeoEvidence> GeoEvidence => Result?.Detail?.Geo?.Evidence ?? [];
    private static string FriendlyReason(TikTokCapabilityResult value)
    {
        if (value.Status == TikTokCapabilityStatus.NotConfigured) return "Тестовое публичное видео не настроено";
        if (value.Status == TikTokCapabilityStatus.Timeout) return "Прокси не ответил за заданное время";
        if (value.Status == TikTokCapabilityStatus.Challenge) return "TikTok показал CAPTCHA или anti-bot challenge";
        return string.IsNullOrWhiteSpace(value.Reason) ? string.Empty : value.Reason.Split('?', 2)[0];
    }
    private string FormatFriendlyExplanation(ProxyCheckResult value)
    {
        var reasons = ExplainProxyFormatter.NotRecommendedReasons(value, geoOptions);
        var text = value.RecommendationClass switch
        {
            ProxyRecommendationClass.Recommended => "Прокси прошёл необходимые проверки и рекомендован для осторожного использования.",
            ProxyRecommendationClass.StablePageAccess => "Прокси стабильно открывает TikTok.",
            ProxyRecommendationClass.PageOnly or ProxyRecommendationClass.VideoPageAccessible => "Прокси открывает страницу TikTok, но полная стабильность или воспроизведение пока не подтверждены.",
            ProxyRecommendationClass.TikTokAccessibleGeoUnknown => "Прокси технически открывает TikTok, но страна выходного IP не подтверждена.",
            _ => "Прокси прошёл только часть технических проверок."
        };
        if (value.RecommendationClass == ProxyRecommendationClass.Recommended) return text;
        var localized = new List<string>();
        if (!GeoPolicy.IsRecommendationEligible(value.Geo, geoOptions)) localized.Add($"достоверность геолокации ниже требуемой ({StatusText.GeoConfidence(geoOptions.MinimumConfidenceForRecommendation)})");
        if (value.ExitIp?.Status != ExitIpStatus.Resolved) localized.Add("выходной IP не подтверждён");
        if ((value.TikTokPageStability ?? value.Stability)?.Status != ProxyStabilityStatus.Stable) localized.Add("стабильность доступа к TikTok пока не подтверждена");
        if (value.PlaybackCapability is not (PlaybackCapability.EmbedPlaybackVerified or PlaybackCapability.FullPlaybackVerified)) localized.Add("воспроизведение видео не проверялось или не подтверждено");
        if (value.TikTokCapabilities.Any(x => x.Status == TikTokCapabilityStatus.Challenge)) localized.Add("обнаружен CAPTCHA или anti-bot challenge");
        if (value.Endpoint.HasCredentials) localized.Add("прокси требует credentials и не экспортируется в пользовательские списки");
        if (localized.Count == 0 && reasons.Count > 0) localized.Add("не выполнены все правила класса Recommended");
        return text + Environment.NewLine + Environment.NewLine + "Он пока не рекомендован, потому что:" + Environment.NewLine
            + string.Join(Environment.NewLine, localized.Select(x => "• " + x + "."));
    }
}

public sealed record CapabilityDisplayItem(string Name, string Status, double LatencyMs, string Reason);
