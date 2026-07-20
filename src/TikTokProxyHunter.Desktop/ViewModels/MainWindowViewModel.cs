using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Desktop.Models;
using TikTokProxyHunter.Desktop.Services;

namespace TikTokProxyHunter.Desktop.ViewModels;

public sealed partial class MainWindowViewModel : ObservableObject
{
    private readonly INavigationService _navigation;
    private readonly IDesktopSettingsService _settingsService;
    private readonly DashboardViewModel _dashboard;
    private readonly ResultsViewModel _results;
    private readonly SourcesViewModel _sources;
    private readonly HistoryViewModel _history;
    private readonly SettingsViewModel _settingsViewModel;
    private readonly DiagnosticsViewModel _diagnostics;
    private DesktopSettings _settings = new();

    public MainWindowViewModel(INavigationService navigation, IDesktopSettingsService settingsService, PipelineUiAdapter pipeline,
        DashboardViewModel dashboard, ResultsViewModel results, SourcesViewModel sources, HistoryViewModel history,
        SettingsViewModel settingsViewModel, DiagnosticsViewModel diagnostics)
    {
        _navigation = navigation; _settingsService = settingsService; _dashboard = dashboard; _results = results;
        _sources = sources; _history = history; _settingsViewModel = settingsViewModel; _diagnostics = diagnostics;
        NavigationItems = [
            new("Dashboard", "Главная", "\uE80F", "Главная"), new("Scan", "Поиск", "\uE721", "Поиск прокси"),
            new("Results", "Результаты", "\uE9D2", "Результаты"), new("Sources", "Источники", "\uE774", "Источники"),
            new("History", "История", "\uE81C", "История запусков"), new("Diagnostics", "Диагностика", "\uE90F", "Диагностика"),
            new("Settings", "Настройки", "\uE713", "Настройки")];
        _navigation.Navigated += (_, vm) => { CurrentViewModel = vm; SelectedPage = NavigationItems.FirstOrDefault(x => vm.GetType().Name.StartsWith(x.Key, StringComparison.OrdinalIgnoreCase))?.Key ?? SelectedPage; };
        pipeline.Changed += (_, _) =>
        {
            RunStatus = StatusText.RunStatus(pipeline.State.Status); CurrentStage = pipeline.State.CurrentStage is { } stage ? StatusText.Stage(stage) : "Готово";
            WorkingCount = pipeline.State.TikTokAccessible; Elapsed = pipeline.State.StartedAt is { } start ? DateTimeOffset.UtcNow - start : TimeSpan.Zero;
        };
        NavigateCommand = new RelayCommand<string>(Navigate);
        ToggleNavigationCommand = new RelayCommand(() => IsNavigationCompact = !IsNavigationCompact);
        NewSearchCommand = new AsyncRelayCommand(() => _dashboard.StartQuickSearchCommand.ExecuteAsync(null));
        ExportCommand = new AsyncRelayCommand(ExportAsync);
        RefreshCommand = new AsyncRelayCommand(RefreshAsync);
        EscapeCommand = new RelayCommand(Escape);
    }

    public ObservableCollection<NavigationItem> NavigationItems { get; }
    public IRelayCommand<string> NavigateCommand { get; }
    public IRelayCommand ToggleNavigationCommand { get; }
    public IAsyncRelayCommand NewSearchCommand { get; }
    public IAsyncRelayCommand ExportCommand { get; }
    public IAsyncRelayCommand RefreshCommand { get; }
    public IRelayCommand EscapeCommand { get; }
    [ObservableProperty] private object? currentViewModel;
    [ObservableProperty] private string selectedPage = "Dashboard";
    [ObservableProperty] private bool isNavigationCompact;
    [ObservableProperty] private string runStatus = "Готово";
    [ObservableProperty] private string currentStage = "Нет активного запуска";
    [ObservableProperty] private long workingCount;
    [ObservableProperty] private TimeSpan elapsed;
    public double NavigationWidth => IsNavigationCompact ? 76 : 220;
    public bool AreNavigationLabelsVisible => !IsNavigationCompact;
    partial void OnIsNavigationCompactChanged(bool value) { OnPropertyChanged(nameof(NavigationWidth)); OnPropertyChanged(nameof(AreNavigationLabelsVisible)); }

    public async Task InitializeAsync()
    {
        var loaded = await _settingsService.LoadAsync(); _settings = loaded.Settings; IsNavigationCompact = _settings.NavigationCompact;
        Navigate(string.IsNullOrWhiteSpace(_settings.LastPage) ? "Dashboard" : _settings.LastPage);
    }

    public async Task SaveWindowStateAsync(double left, double top, double width, double height)
    {
        var current = (await _settingsService.LoadAsync()).Settings;
        _settings = current with { LastPage = SelectedPage, NavigationCompact = IsNavigationCompact,
            WindowLeft = left, WindowTop = top, WindowWidth = width, WindowHeight = height };
        await _settingsService.SaveAsync(_settings);
    }
    public DesktopSettings Settings => _settings;
    private void Navigate(string? key) { if (!string.IsNullOrWhiteSpace(key)) _navigation.Navigate(key); }
    private async Task ExportAsync()
    {
        _navigation.Navigate("Results"); await _results.InitializeAsync();
        if (_results.ExportCommand.CanExecute(null)) await _results.ExportCommand.ExecuteAsync(null);
    }
    private Task RefreshAsync() => CurrentViewModel switch
    {
        DashboardViewModel => _dashboard.InitializeAsync(), ResultsViewModel => _results.InitializeAsync(),
        SourcesViewModel => _sources.LoadAsync(), HistoryViewModel => _history.LoadAsync(),
        SettingsViewModel => _settingsViewModel.InitializeAsync(), DiagnosticsViewModel => _diagnostics.RefreshAsync(),
        _ => Task.CompletedTask
    };
    private void Escape()
    {
        if (CurrentViewModel is ProxyDetailsViewModel) _navigation.Navigate("Results");
        else if (CurrentViewModel is ResultsViewModel) _results.SelectedResult = null;
    }
}
