using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Desktop.Models;
using TikTokProxyHunter.Desktop.Services;
using TikTokProxyHunter.Infrastructure;

namespace TikTokProxyHunter.Desktop.ViewModels;

public sealed partial class ResultsViewModel : ObservableObject
{
    private readonly DesktopSession _session; private readonly IResultStore _store; private readonly IRunHistoryService _history;
    private readonly IDesktopSettingsService _settings; private readonly IClipboardService _clipboard; private readonly INavigationService _navigation;
    private readonly ProxyDetailsViewModel _details; private readonly Stage2ResultExporter _exporter; private readonly GeoOptions _geoOptions;
    private IReadOnlyList<ProxyResultItem> _all = []; private int _displayLimit = 500;

    public ResultsViewModel(DesktopSession session, IResultStore store, IRunHistoryService history, IDesktopSettingsService settings,
        IClipboardService clipboard, INavigationService navigation, ProxyDetailsViewModel details,
        Stage2ResultExporter exporter, GeoOptions geoOptions)
    {
        _session = session; _store = store; _history = history; _settings = settings; _clipboard = clipboard;
        _navigation = navigation; _details = details; _exporter = exporter; _geoOptions = geoOptions;
        Results = []; session.Changed += (_, _) => LoadFromSession();
        CopyProxyCommand = new AsyncRelayCommand(async () => { if (SelectedResult is not null) await _clipboard.CopyProxyUrlAsync(SelectedResult); }, () => SelectedResult is not null);
        CopyEndpointCommand = new RelayCommand(() => { if (SelectedResult is not null && !SelectedResult.HasCredentials) _clipboard.CopyText(SelectedResult.Address); }, () => SelectedResult is not null);
        OpenDetailsCommand = new RelayCommand(OpenDetails, () => SelectedResult is not null);
        ToggleFavoriteCommand = new RelayCommand(() => { if (SelectedResult is not null) { SelectedResult.IsFavorite = !SelectedResult.IsFavorite; ApplyFilters(); } }, () => SelectedResult is not null);
        LoadMoreCommand = new RelayCommand(() => { _displayLimit += 500; ApplyFilters(); }, () => Results.Count < FilteredCount);
        ExportCommand = new AsyncRelayCommand(ExportAsync, () => _session.LastRun is not null);
        OpenFolderCommand = new RelayCommand(OpenFolder, () => Directory.Exists(_session.LastOutputDirectory));
        RefreshCommand = new AsyncRelayCommand(InitializeAsync);
        RecheckCommand = new RelayCommand(() => _navigation.Navigate("Scan"), () => SelectedResult is not null);
    }
    public ObservableCollection<ProxyResultItem> Results { get; }
    public IReadOnlyList<string> ClassFilters { get; } = ["Все", "Recommended", "FullPlaybackVerified", "EmbedPlaybackVerified", "StablePageAccess", "PageOnly", "GeoUnknown"];
    public IReadOnlyList<string> ProtocolFilters { get; } = ["Все", "SOCKS5", "HTTP CONNECT", "SOCKS4", "HTTP"];
    public IAsyncRelayCommand CopyProxyCommand { get; }
    public IRelayCommand CopyEndpointCommand { get; }
    public IRelayCommand OpenDetailsCommand { get; }
    public IRelayCommand ToggleFavoriteCommand { get; }
    public IRelayCommand LoadMoreCommand { get; }
    public IAsyncRelayCommand ExportCommand { get; }
    public IRelayCommand OpenFolderCommand { get; }
    public IAsyncRelayCommand RefreshCommand { get; }
    public IRelayCommand RecheckCommand { get; }
    [ObservableProperty] private ProxyResultItem? selectedResult;
    [ObservableProperty] private string classFilter = "Все";
    [ObservableProperty] private string protocolFilter = "Все";
    [ObservableProperty] private string countryFilter = string.Empty;
    [ObservableProperty] private string searchText = string.Empty;
    [ObservableProperty] private double maximumLatency;
    [ObservableProperty] private bool credentialsFreeOnly = true;
    [ObservableProperty] private int filteredCount;
    [ObservableProperty] private string runTitle = "Результатов пока нет";
    public bool HasResults => Results.Count > 0;

    public async Task InitializeAsync()
    {
        if (_session.LastRun is not null) { LoadFromSession(); return; }
        var settings = (await _settings.LoadAsync()).Settings; var history = await _history.LoadAsync(settings.OutputDirectory);
        var latest = history.FirstOrDefault(); if (latest is null) { ApplyFilters(); return; }
        await LoadRunAsync(latest);
    }
    public async Task LoadRunAsync(RunHistoryItem item)
    {
        var values = await _store.LoadSafeAsync(item.Directory);
        _session.SetRun(new HunterRunResult { Summary = item.Manifest.Summary,
            Results = values.Select(x => x.Detail!).Where(x => x is not null).ToArray(),
            SourceHealth = await _store.LoadSourceHealthAsync(item.Directory) });
        _all = values; RunTitle = $"Результаты от {item.StartedAt:dd MMMM yyyy, HH:mm}"; ApplyFilters();
        ExportCommand.NotifyCanExecuteChanged(); OpenFolderCommand.NotifyCanExecuteChanged();
    }
    partial void OnSelectedResultChanged(ProxyResultItem? value)
    { CopyProxyCommand.NotifyCanExecuteChanged(); CopyEndpointCommand.NotifyCanExecuteChanged(); OpenDetailsCommand.NotifyCanExecuteChanged(); ToggleFavoriteCommand.NotifyCanExecuteChanged(); RecheckCommand.NotifyCanExecuteChanged(); }
    partial void OnClassFilterChanged(string value) => ApplyFilters();
    partial void OnProtocolFilterChanged(string value) => ApplyFilters();
    partial void OnCountryFilterChanged(string value) => ApplyFilters();
    partial void OnSearchTextChanged(string value) => ApplyFilters();
    partial void OnMaximumLatencyChanged(double value) => ApplyFilters();
    partial void OnCredentialsFreeOnlyChanged(bool value) => ApplyFilters();
    private void LoadFromSession()
    {
        var run = _session.LastRun; if (run is null) return;
        _all = run.Results.Select(ProxyResultItem.From).ToArray();
        RunTitle = $"Результаты от {run.Summary.StartedAt:dd MMMM yyyy, HH:mm}"; ApplyFilters(); ExportCommand.NotifyCanExecuteChanged(); OpenFolderCommand.NotifyCanExecuteChanged();
    }
    private void ApplyFilters()
    {
        var filtered = ProxyResultQuery.Apply(_all, ClassFilter, ProtocolFilter, CountryFilter, SearchText, MaximumLatency, CredentialsFreeOnly).ToArray();
        FilteredCount = filtered.Length; Results.Clear(); foreach (var item in filtered.Take(_displayLimit)) Results.Add(item);
        OnPropertyChanged(nameof(HasResults)); LoadMoreCommand.NotifyCanExecuteChanged();
    }
    private void OpenDetails() { if (SelectedResult is null) return; _details.SetResult(SelectedResult); _navigation.Navigate("ProxyDetails"); }
    private async Task ExportAsync()
    {
        if (_session.LastRun is not { } run) return;
        await _exporter.ExportUserListsAsync(Path.Combine(run.Summary.OutputDirectory, "user-proxies"), run.Results, _geoOptions, false, CancellationToken.None);
    }
    private void OpenFolder()
    {
        var path = _session.LastOutputDirectory; if (path is null || !Directory.Exists(path)) return;
        Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true });
    }
}
