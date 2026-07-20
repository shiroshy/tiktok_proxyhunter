using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Desktop.Models;
using TikTokProxyHunter.Desktop.Services;

namespace TikTokProxyHunter.Desktop.ViewModels;

public sealed partial class SourcesViewModel : ObservableObject
{
    private readonly ISourceCatalogService _catalog; private readonly IDesktopSettingsService _settings;
    private readonly DesktopSession _session; private readonly IDialogService _dialogs;
    private readonly ISourceReviewService _review;
    private string _path = string.Empty; private IReadOnlyList<SourceHealthItem> _all = [];
    public SourcesViewModel(ISourceCatalogService catalog, IDesktopSettingsService settings, DesktopSession session, IDialogService dialogs,
        ISourceReviewService review)
    {
        _catalog = catalog; _settings = settings; _session = session; _dialogs = dialogs; _review = review; Sources = [];
        RefreshCommand = new AsyncRelayCommand(LoadAsync); ToggleCommand = new AsyncRelayCommand(ToggleAsync, () => SelectedSource is not null);
        OpenHomepageCommand = new RelayCommand(OpenHomepage, () => SelectedSource is not null && Uri.TryCreate(SelectedSource.Homepage, UriKind.Absolute, out _));
        PreviewImportCommand = new AsyncRelayCommand(PreviewImportAsync);
    }
    public ObservableCollection<SourceHealthItem> Sources { get; }
    public IReadOnlyList<string> Filters { get; } = ["Все", "Включённые", "Отключённые", "Healthy", "Degraded", "Unavailable", "Без известной лицензии"];
    public IAsyncRelayCommand RefreshCommand { get; }
    public IAsyncRelayCommand ToggleCommand { get; }
    public IRelayCommand OpenHomepageCommand { get; }
    public IAsyncRelayCommand PreviewImportCommand { get; }
    [ObservableProperty] private SourceHealthItem? selectedSource;
    [ObservableProperty] private string filter = "Все";
    [ObservableProperty] private string statusMessage = string.Empty;
    partial void OnFilterChanged(string value) => ApplyFilter();
    partial void OnSelectedSourceChanged(SourceHealthItem? value) { ToggleCommand.NotifyCanExecuteChanged(); OpenHomepageCommand.NotifyCanExecuteChanged(); }

    public async Task LoadAsync()
    {
        var settings = (await _settings.LoadAsync()).Settings; _path = AppPathResolver.ResolveConfig(settings.SourcesPath);
        var definitions = await _catalog.LoadAsync(_path); var health = _session.LastRun?.SourceHealth.ToDictionary(x => x.SourceName, StringComparer.OrdinalIgnoreCase)
            ?? new Dictionary<string, ProxySourceHealth>(StringComparer.OrdinalIgnoreCase);
        _all = definitions.Select(source =>
        {
            health.TryGetValue(source.Name, out var state);
            return new SourceHealthItem { Name = source.Name, Family = source.SourceFamily ?? source.Name,
                Protocol = StatusText.Protocol(source.DeclaredProtocol), Enabled = source.Enabled,
                Status = state?.Status ?? (source.Enabled ? ProxySourceHealthStatus.Unavailable : ProxySourceHealthStatus.Disabled),
                Candidates = state?.ExtractedRows ?? 0, Valid = state?.ValidCandidates ?? 0,
                LatencyMs = state?.DownloadTime.TotalMilliseconds ?? 0, LastSuccess = state?.LastSuccess,
                License = source.License ?? "Неизвестна", Homepage = source.Homepage ?? string.Empty, Reason = state?.Reason ?? source.Notes };
        }).ToArray(); ApplyFilter(); StatusMessage = $"Источников: {_all.Count}; включено: {_all.Count(x => x.Enabled)}";
    }
    private async Task ToggleAsync()
    {
        if (SelectedSource is null) return;
        if (!SelectedSource.Enabled && SelectedSource.License.Equals("Неизвестна", StringComparison.OrdinalIgnoreCase)
            && !await _dialogs.ConfirmAsync("Неизвестная лицензия", "У источника не указана лицензия. Убедитесь, что автоматическое получение списка разрешено. Включить?")) return;
        await _catalog.SetEnabledAsync(_path, SelectedSource.Name, !SelectedSource.Enabled); await LoadAsync();
    }
    private void ApplyFilter()
    {
        var query = _all.AsEnumerable(); query = Filter switch
        {
            "Включённые" => query.Where(x => x.Enabled), "Отключённые" => query.Where(x => !x.Enabled),
            "Healthy" => query.Where(x => x.Status == ProxySourceHealthStatus.Healthy),
            "Degraded" => query.Where(x => x.Status == ProxySourceHealthStatus.Degraded),
            "Unavailable" => query.Where(x => x.Status == ProxySourceHealthStatus.Unavailable),
            "Без известной лицензии" => query.Where(x => x.License.Equals("Неизвестна", StringComparison.OrdinalIgnoreCase)), _ => query
        };
        Sources.Clear(); foreach (var item in query) Sources.Add(item);
    }
    private void OpenHomepage()
    { if (SelectedSource is not null && Uri.TryCreate(SelectedSource.Homepage, UriKind.Absolute, out var uri))
        Process.Start(new ProcessStartInfo { FileName = uri.AbsoluteUri, UseShellExecute = true }); }
    private async Task PreviewImportAsync() => StatusMessage = await _review.PreviewImportAsync(_path);
}
