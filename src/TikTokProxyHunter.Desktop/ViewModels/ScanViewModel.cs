using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Desktop.Models;
using TikTokProxyHunter.Desktop.Services;

namespace TikTokProxyHunter.Desktop.ViewModels;

public sealed partial class ScanViewModel : ObservableObject
{
    private readonly IHunterRunController _controller; private readonly PipelineUiAdapter _adapter;
    private readonly DesktopSession _session; private readonly IDesktopSettingsService _settingsService;
    private readonly IDialogService _dialogs; private readonly INavigationService _navigation;

    public ScanViewModel(IHunterRunController controller, PipelineUiAdapter adapter, DesktopSession session,
        IDesktopSettingsService settingsService, IDialogService dialogs, INavigationService navigation, IClipboardService clipboard)
    {
        _controller = controller; _adapter = adapter; _session = session; _settingsService = settingsService;
        _dialogs = dialogs; _navigation = navigation; Clipboard = clipboard;
        Stages = new ObservableCollection<PipelineStageItem>(adapter.Stages);
        adapter.Changed += (_, _) => RefreshProgress();
        CancelCommand = new AsyncRelayCommand(CancelAsync, () => IsRunning);
        OpenResultsCommand = new RelayCommand(() => navigation.Navigate("Results"), () => session.LastRun is not null);
        StartNewCommand = new AsyncRelayCommand(async () => await StartAsync(new UiRunConfiguration()));
    }
    public IClipboardService Clipboard { get; }
    public ObservableCollection<PipelineStageItem> Stages { get; }
    public IAsyncRelayCommand CancelCommand { get; }
    public IRelayCommand OpenResultsCommand { get; }
    public IAsyncRelayCommand StartNewCommand { get; }
    [ObservableProperty] private HunterRunStatus status = HunterRunStatus.Idle;
    [ObservableProperty] private string statusLabel = "Готово к поиску";
    [ObservableProperty] private string currentStage = "Нет активного запуска";
    [ObservableProperty] private string currentStageProgress = string.Empty;
    [ObservableProperty] private DateTimeOffset? startedAt;
    [ObservableProperty] private double overallProgress;
    [ObservableProperty] private bool isIndeterminate;
    [ObservableProperty] private long collected;
    [ObservableProperty] private long unique;
    [ObservableProperty] private long protocolAlive;
    [ObservableProperty] private long genericHttps;
    [ObservableProperty] private long tikTokAccessible;
    [ObservableProperty] private long stable;
    [ObservableProperty] private long rejectedRussia;
    [ObservableProperty] private string outputDirectory = string.Empty;
    public bool IsRunning => Status is HunterRunStatus.Preparing or HunterRunStatus.Running or HunterRunStatus.Cancelling;

    public async Task StartAsync(UiRunConfiguration ui)
    {
        var errors = ui.Validate(); if (errors.Count > 0)
        { await _dialogs.ShowErrorAsync(new("Невозможно начать поиск", string.Join(Environment.NewLine, errors), ["Исправьте настройки поиска"], string.Empty)); return; }
        var loaded = await _settingsService.LoadAsync(); var settings = loaded.Settings;
        await _settingsService.SaveAsync(settings with { QuickScan = ui });
        var output = Path.Combine(settings.OutputDirectory, DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmss.fffZ"));
        var videos = ui.CheckPublicVideo && Uri.TryCreate(ui.PublicVideoUrl, UriKind.Absolute, out var video) ? new[] { video } : [];
        var configuration = new HunterRunConfiguration { SourcesPath = AppPathResolver.ResolveConfig(settings.SourcesPath),
            OutputDirectory = output, MaximumCandidates = ui.MaximumCandidates, Concurrency = ui.Concurrency,
            TimeoutSeconds = ui.TimeoutSeconds, AllowUnknownGeoForTechnicalCheck = ui.AllowUnknownGeo,
            AllowConflictingGeoForTechnicalCheck = ui.AllowUnknownGeo, RejectLikelyRussia = settings.RejectLikelyRussia,
            MinimumGeoConfidenceForRecommendation = settings.MinimumGeoConfidence, PublicVideoUrls = videos,
            BrowserVerificationEnabled = ui.BrowserVerification, BrowserLimit = ui.BrowserLimit, StabilityAttempts = ui.StabilityAttempts };
        await RunAsync(configuration, settings.AutoOpenResults);
    }

    public async Task ResumeAsync(RunHistoryItem item)
    {
        var configuration = item.Manifest.Configuration with { Resume = true, ResumeRunDirectory = item.Directory,
            OutputDirectory = item.Directory, SourcesPath = AppPathResolver.ResolveConfig(item.Manifest.Configuration.SourcesPath) };
        await RunAsync(configuration, true);
    }

    private async Task RunAsync(HunterRunConfiguration configuration, bool autoOpen)
    {
        if (_controller.IsRunActive) return; _adapter.Reset(); OutputDirectory = configuration.OutputDirectory;
        Status = HunterRunStatus.Preparing; StartedAt = DateTimeOffset.UtcNow; OnPropertyChanged(nameof(IsRunning)); CancelCommand.NotifyCanExecuteChanged();
        var result = await _controller.StartAsync(configuration, _adapter);
        _session.SetRun(result); Status = result.Summary.Status; StatusLabel = StatusText.RunStatus(Status);
        RejectedRussia = result.Summary.RejectedRussia; OnPropertyChanged(nameof(IsRunning)); CancelCommand.NotifyCanExecuteChanged(); OpenResultsCommand.NotifyCanExecuteChanged();
        if (result.Summary.Failure is { } failure) await _dialogs.ShowErrorAsync(ErrorPresentation.From(failure));
        else if (result.Summary.Status == HunterRunStatus.Cancelled)
            await _dialogs.ShowInformationAsync("Поиск остановлен", "Checkpoint и частичные результаты сохранены. Запуск можно продолжить позже.");
        if (autoOpen && result.Results.Count > 0) _navigation.Navigate("Results");
    }

    private async Task CancelAsync()
    {
        if (!IsRunning) return;
        if (!await _dialogs.ConfirmAsync("Остановить поиск?", "Workers будут корректно остановлены, а checkpoint и частичные результаты сохранены.")) return;
        Status = HunterRunStatus.Cancelling; StatusLabel = "Корректная остановка…"; await _controller.CancelAsync();
    }

    private void RefreshProgress()
    {
        var state = _adapter.State; Status = state.Status; StatusLabel = state.StatusText; StartedAt = state.StartedAt;
        Collected = state.Collected; Unique = state.Unique; ProtocolAlive = state.ProtocolAlive; GenericHttps = state.GenericHttps;
        TikTokAccessible = state.TikTokAccessible; Stable = state.Stable; RejectedRussia = state.RejectedRussia;
        Stages.Clear(); foreach (var stage in _adapter.Stages) Stages.Add(stage);
        var current = state.CurrentStage is { } currentStageKey ? Stages.FirstOrDefault(x => x.Stage == currentStageKey) : Stages.FirstOrDefault(x => x.Status == HunterStageStatus.Running);
        CurrentStage = current?.Name ?? (Status == HunterRunStatus.Completed ? "Поиск завершён" : "Подготовка");
        CurrentStageProgress = current is null ? string.Empty : current.Total is { } total ? $"{current.Processed:N0} / {total:N0}" : $"{current.Processed:N0}";
        IsIndeterminate = current?.IsIndeterminate == true;
        var completed = Stages.Count(x => x.Status is HunterStageStatus.Completed or HunterStageStatus.CompletedWithWarnings or HunterStageStatus.Skipped);
        var fraction = current?.Total is > 0 ? current.Processed / (double)current.Total.Value : 0;
        OverallProgress = Math.Clamp((completed + fraction) / Math.Max(1, Stages.Count) * 100, 0, 100);
        OnPropertyChanged(nameof(IsRunning)); CancelCommand.NotifyCanExecuteChanged();
    }
}
