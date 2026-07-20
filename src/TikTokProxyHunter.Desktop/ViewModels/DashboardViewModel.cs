using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Desktop.Models;
using TikTokProxyHunter.Desktop.Services;

namespace TikTokProxyHunter.Desktop.ViewModels;

public sealed partial class DashboardViewModel : ObservableObject
{
    private readonly DesktopSession _session; private readonly INavigationService _navigation;
    private readonly ScanViewModel _scan; private readonly IQuickScanDialogService _quickDialog;
    private readonly IRunHistoryService _history; private readonly IDesktopSettingsService _settings;
    private readonly IResultStore _resultStore;
    private RunHistoryItem? _resumeItem;

    public DashboardViewModel(DesktopSession session, INavigationService navigation, ScanViewModel scan,
        IQuickScanDialogService quickDialog, IRunHistoryService history, IDesktopSettingsService settings, IResultStore resultStore)
    {
        _session = session; _navigation = navigation; _scan = scan; _quickDialog = quickDialog; _history = history; _settings = settings; _resultStore = resultStore;
        session.Changed += (_, _) => Refresh();
        StartQuickSearchCommand = new AsyncRelayCommand(StartQuickAsync);
        ConfigureSearchCommand = new RelayCommand(() => navigation.Navigate("Settings"));
        ContinueCommand = new AsyncRelayCommand(ContinueAsync, () => CanContinue);
        OpenBestCommand = new RelayCommand(() => navigation.Navigate("Results"), () => BestProxy is not null);
        CopyBestCommand = new AsyncRelayCommand(async () => { if (BestProxy is not null) await scan.Clipboard.CopyProxyUrlAsync(BestProxy); }, () => BestProxy is not null);
    }
    public IAsyncRelayCommand StartQuickSearchCommand { get; }
    public IRelayCommand ConfigureSearchCommand { get; }
    public IAsyncRelayCommand ContinueCommand { get; }
    public IRelayCommand OpenBestCommand { get; }
    public IAsyncRelayCommand CopyBestCommand { get; }
    [ObservableProperty] private long candidates;
    [ObservableProperty] private long working;
    [ObservableProperty] private long tikTokAccessible;
    [ObservableProperty] private long stable;
    [ObservableProperty] private long playbackVerified;
    [ObservableProperty] private long recommended;
    [ObservableProperty] private ProxyResultItem? bestProxy;
    [ObservableProperty] private bool canContinue;
    public bool HasLastRun => _session.LastRun is not null;

    public async Task InitializeAsync()
    {
        var settings = (await _settings.LoadAsync()).Settings;
        var history = await _history.LoadAsync(settings.OutputDirectory);
        if (_session.LastRun is null && history.FirstOrDefault() is { } latest)
        {
            var items = await _resultStore.LoadSafeAsync(latest.Directory);
            _session.SetRun(new HunterRunResult
            {
                Summary = latest.Manifest.Summary,
                Results = items.Select(x => x.Detail).Where(x => x is not null).Cast<ProxyCheckResult>().ToArray(),
                SourceHealth = await _resultStore.LoadSourceHealthAsync(latest.Directory)
            });
        }
        _resumeItem = history.FirstOrDefault(x => x.CanResume); CanContinue = _resumeItem is not null;
        ContinueCommand.NotifyCanExecuteChanged(); Refresh();
    }

    private async Task StartQuickAsync()
    {
        var settings = (await _settings.LoadAsync()).Settings;
        var config = await _quickDialog.ShowAsync(settings.QuickScan); if (config is null) return;
        _navigation.Navigate("Scan"); await _scan.StartAsync(config);
    }
    private async Task ContinueAsync()
    {
        if (_resumeItem is null) return; _navigation.Navigate("Scan"); await _scan.ResumeAsync(_resumeItem);
    }
    private void Refresh()
    {
        var run = _session.LastRun; if (run is null) return;
        Candidates = run.Summary.Unique; Working = run.Summary.ProtocolAlive; TikTokAccessible = run.Summary.TikTokAccessible;
        Stable = run.Summary.Stable; PlaybackVerified = run.Summary.PlaybackVerified; Recommended = run.Summary.Recommended;
        BestProxy = run.Results.Select(ProxyResultItem.From).Where(x => !x.HasCredentials)
            .OrderByDescending(x => ProxyResultQuery.QualityRank(x.RecommendationClass)).ThenByDescending(x => x.Score).FirstOrDefault();
        OnPropertyChanged(nameof(HasLastRun)); OpenBestCommand.NotifyCanExecuteChanged(); CopyBestCommand.NotifyCanExecuteChanged();
    }
}
