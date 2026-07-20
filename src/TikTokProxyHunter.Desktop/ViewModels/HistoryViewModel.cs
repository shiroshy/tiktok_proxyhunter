using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TikTokProxyHunter.Desktop.Models;
using TikTokProxyHunter.Desktop.Services;

namespace TikTokProxyHunter.Desktop.ViewModels;

public sealed partial class HistoryViewModel : ObservableObject
{
    private readonly IRunHistoryService _history; private readonly IDesktopSettingsService _settings;
    private readonly IDialogService _dialogs; private readonly ScanViewModel _scan; private readonly INavigationService _navigation; private readonly ResultsViewModel _results;
    private string _outputRoot = string.Empty;
    public HistoryViewModel(IRunHistoryService history, IDesktopSettingsService settings, IDialogService dialogs, ScanViewModel scan, INavigationService navigation, ResultsViewModel results)
    {
        _history = history; _settings = settings; _dialogs = dialogs; _scan = scan; _navigation = navigation; _results = results; Runs = [];
        RefreshCommand = new AsyncRelayCommand(LoadAsync); OpenResultsCommand = new AsyncRelayCommand<RunHistoryItem>(OpenResultsAsync);
        ResumeCommand = new AsyncRelayCommand<RunHistoryItem>(ResumeAsync, item => item?.CanResume == true);
        RepeatCommand = new AsyncRelayCommand<RunHistoryItem>(RepeatAsync);
        OpenFolderCommand = new RelayCommand<RunHistoryItem>(OpenFolder);
        DeleteCommand = new AsyncRelayCommand<RunHistoryItem>(DeleteAsync);
    }
    public ObservableCollection<RunHistoryItem> Runs { get; }
    public IAsyncRelayCommand RefreshCommand { get; }
    public IAsyncRelayCommand<RunHistoryItem> OpenResultsCommand { get; }
    public IAsyncRelayCommand<RunHistoryItem> ResumeCommand { get; }
    public IAsyncRelayCommand<RunHistoryItem> RepeatCommand { get; }
    public IRelayCommand<RunHistoryItem> OpenFolderCommand { get; }
    public IAsyncRelayCommand<RunHistoryItem> DeleteCommand { get; }
    [ObservableProperty] private RunHistoryItem? selectedRun;
    [ObservableProperty] private string emptyMessage = "История запусков пуста";
    public async Task LoadAsync()
    {
        var settings = (await _settings.LoadAsync()).Settings; _outputRoot = settings.OutputDirectory;
        var values = await _history.LoadAsync(_outputRoot); Runs.Clear(); foreach (var value in values) Runs.Add(value);
        EmptyMessage = values.Count == 0 ? "Завершённые запуски появятся здесь" : string.Empty;
    }
    private async Task OpenResultsAsync(RunHistoryItem? item) { if (item is null) return; await _results.LoadRunAsync(item); _navigation.Navigate("Results"); }
    private async Task ResumeAsync(RunHistoryItem? item) { if (item is null) return; _navigation.Navigate("Scan"); await _scan.ResumeAsync(item); }
    private async Task RepeatAsync(RunHistoryItem? item)
    {
        if (item is null) return; var c = item.Manifest.Configuration;
        var ui = new UiRunConfiguration { Preset = ScanPreset.Custom, MaximumCandidates = c.MaximumCandidates,
            CheckPublicVideo = c.PublicVideoUrls.Count > 0, PublicVideoUrl = c.PublicVideoUrls.FirstOrDefault()?.AbsoluteUri ?? string.Empty,
            BrowserVerification = c.BrowserVerificationEnabled, AllowUnknownGeo = c.AllowUnknownGeoForTechnicalCheck,
            Concurrency = c.Concurrency, TimeoutSeconds = c.TimeoutSeconds, StabilityAttempts = c.StabilityAttempts, BrowserLimit = c.BrowserLimit };
        _navigation.Navigate("Scan"); await _scan.StartAsync(ui);
    }
    private static void OpenFolder(RunHistoryItem? item) { if (item is not null) Process.Start(new ProcessStartInfo { FileName = item.Directory, UseShellExecute = true }); }
    private async Task DeleteAsync(RunHistoryItem? item)
    {
        if (item is null) return;
        if (!await _dialogs.ConfirmAsync("Удалить запись и файлы запуска?", $"Будет безвозвратно удалена папка:\n{item.Directory}")) return;
        await _history.DeleteAsync(item, _outputRoot); await LoadAsync();
    }
}
