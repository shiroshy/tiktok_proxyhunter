using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Desktop.Models;
using TikTokProxyHunter.Desktop.Services;
using TikTokProxyHunter.Infrastructure;

namespace TikTokProxyHunter.Desktop.ViewModels;

public sealed partial class SettingsViewModel : ObservableObject
{
    private readonly IDesktopSettingsService _service; private readonly IThemeService _themeService;
    private readonly IBrowserDoctor _browserDoctor; private readonly ILocalGeoIpProvider _geoProvider;
    private readonly IChromiumInstaller _installer; private readonly IFilePickerService _picker;
    private readonly IDialogService _dialogs; private DesktopSettings _loaded = new();
    private readonly ISourceReviewService _sourceReview;
    public SettingsViewModel(IDesktopSettingsService service, IThemeService themeService, IBrowserDoctor browserDoctor,
        ILocalGeoIpProvider geoProvider, IChromiumInstaller installer, IFilePickerService picker, IDialogService dialogs,
        ISourceReviewService sourceReview)
    {
        _service = service; _themeService = themeService; _browserDoctor = browserDoctor; _geoProvider = geoProvider;
        _installer = installer; _picker = picker; _dialogs = dialogs; _sourceReview = sourceReview;
        SaveCommand = new AsyncRelayCommand(SaveAsync); ResetCommand = new AsyncRelayCommand(ResetAsync);
        BrowserDoctorCommand = new AsyncRelayCommand(CheckBrowserAsync); InstallChromiumCommand = new AsyncRelayCommand(InstallChromiumAsync);
        ValidateGeoCommand = new AsyncRelayCommand(ValidateGeoAsync); PickCountryDbCommand = new RelayCommand(() => CountryDatabasePath = _picker.PickMmdb("Выберите country MMDB") ?? CountryDatabasePath);
        PickAsnDbCommand = new RelayCommand(() => AsnDatabasePath = _picker.PickMmdb("Выберите ASN MMDB") ?? AsnDatabasePath);
        AddVideoCommand = new RelayCommand(() => { if (!string.IsNullOrWhiteSpace(NewVideoUrl)) { VideoUrls.Add(NewVideoUrl); NewVideoUrl = string.Empty; } });
        RemoveVideoCommand = new RelayCommand<string>(value => { if (value is not null) VideoUrls.Remove(value); });
        RepeatOnboardingCommand = new AsyncRelayCommand(RepeatOnboardingAsync);
        DiscoverSourcesCommand = new AsyncRelayCommand(DiscoverSourcesAsync);
        PreviewImportCommand = new AsyncRelayCommand(PreviewImportAsync);
    }
    public IReadOnlyList<DesktopTheme> Themes { get; } = Enum.GetValues<DesktopTheme>();
    public ObservableCollection<string> VideoUrls { get; } = [];
    public IAsyncRelayCommand SaveCommand { get; }
    public IAsyncRelayCommand ResetCommand { get; }
    public IAsyncRelayCommand BrowserDoctorCommand { get; }
    public IAsyncRelayCommand InstallChromiumCommand { get; }
    public IAsyncRelayCommand ValidateGeoCommand { get; }
    public IRelayCommand PickCountryDbCommand { get; }
    public IRelayCommand PickAsnDbCommand { get; }
    public IRelayCommand AddVideoCommand { get; }
    public IRelayCommand<string> RemoveVideoCommand { get; }
    public IAsyncRelayCommand RepeatOnboardingCommand { get; }
    public IAsyncRelayCommand DiscoverSourcesCommand { get; }
    public IAsyncRelayCommand PreviewImportCommand { get; }
    public IReadOnlyList<string> GeoConfidenceLevels { get; } = Enum.GetNames<GeoConfidenceLevel>();
    [ObservableProperty] private DesktopTheme theme = DesktopTheme.System;
    [ObservableProperty] private string outputDirectory = string.Empty;
    [ObservableProperty] private string sourcesPath = "config/proxy-sources.json";
    [ObservableProperty] private int defaultCandidates = 3_000;
    [ObservableProperty] private bool autoOpenResults = true;
    [ObservableProperty] private int concurrency = 100;
    [ObservableProperty] private int timeoutSeconds = 5;
    [ObservableProperty] private bool allowUnknownGeo = true;
    [ObservableProperty] private bool rejectLikelyRussia = true;
    [ObservableProperty] private string minimumGeoConfidence = "Medium";
    [ObservableProperty] private int stabilityAttempts = 3;
    [ObservableProperty] private int browserLimit = 10;
    [ObservableProperty] private int browserTimeoutSeconds = 25;
    [ObservableProperty] private bool captureScreenshots;
    [ObservableProperty] private string countryDatabasePath = string.Empty;
    [ObservableProperty] private string asnDatabasePath = string.Empty;
    [ObservableProperty] private string newVideoUrl = string.Empty;
    [ObservableProperty] private string browserState = "Не проверен";
    [ObservableProperty] private string geoState = "Не проверена";
    [ObservableProperty] private string saveState = string.Empty;
    [ObservableProperty] private string sourceOperationState = string.Empty;
    public async Task InitializeAsync()
    {
        var result = await _service.LoadAsync(); _loaded = result.Settings; Apply(_loaded); _themeService.Apply(Theme);
        if (result.Warning is not null) SaveState = result.Warning;
    }
    private async Task SaveAsync()
    {
        var quick = _loaded.QuickScan with { MaximumCandidates = DefaultCandidates, Concurrency = Concurrency,
            TimeoutSeconds = TimeoutSeconds, AllowUnknownGeo = AllowUnknownGeo, StabilityAttempts = StabilityAttempts, BrowserLimit = BrowserLimit };
        _loaded = _loaded with { Theme = Theme, OutputDirectory = Path.GetFullPath(OutputDirectory), SourcesPath = SourcesPath,
            QuickScan = quick, AutoOpenResults = AutoOpenResults, BrowserTimeoutSeconds = BrowserTimeoutSeconds,
            CaptureScreenshotsOnFailure = CaptureScreenshots, CountryDatabasePath = CountryDatabasePath, AsnDatabasePath = AsnDatabasePath,
            RejectLikelyRussia = RejectLikelyRussia,
            MinimumGeoConfidence = Enum.TryParse<GeoConfidenceLevel>(MinimumGeoConfidence, true, out var confidence) ? confidence : GeoConfidenceLevel.Medium,
            TestVideoUrls = VideoUrls.ToArray() };
        await _service.SaveAsync(_loaded); _themeService.Apply(Theme); SaveState = "Настройки сохранены";
    }
    private async Task ResetAsync()
    {
        if (!await _dialogs.ConfirmAsync("Вернуть безопасные настройки?", "Пользовательские параметры проверки будут сброшены. История запусков не удаляется.")) return;
        _loaded = new DesktopSettings { OnboardingCompleted = true }; Apply(_loaded); await _service.SaveAsync(_loaded); _themeService.Apply(Theme); SaveState = "Безопасные настройки восстановлены";
    }
    private async Task CheckBrowserAsync()
    { var result = await _browserDoctor.DiagnoseAsync(CancellationToken.None); BrowserState = result.LaunchSucceeded ? "Chromium установлен и запускается" : $"Недоступен: {result.Reason}"; }
    private async Task InstallChromiumAsync()
    {
        if (!await _dialogs.ConfirmAsync("Установить Chromium?", "Playwright скачает отдельную сборку Chromium. Она не включается в executable и не меняет системный браузер.")) return;
        var progress = new Progress<string>(text => BrowserState = text); var result = await _installer.InstallAsync(progress, CancellationToken.None);
        BrowserState = result.Message; if (result.Success) await CheckBrowserAsync();
    }
    private async Task ValidateGeoAsync()
    { var results = await _geoProvider.ValidateAsync(CancellationToken.None); GeoState = string.Join("; ", results.Select(x => $"{x.DatabaseType}: {(x.Success ? "OK" : x.Reason)}")); }
    private async Task RepeatOnboardingAsync()
    {
        _loaded = _loaded with { OnboardingCompleted = false }; await _service.SaveAsync(_loaded);
        await _dialogs.ShowInformationAsync("Первичная настройка", "Onboarding будет показан при следующем запуске приложения.");
    }
    private async Task DiscoverSourcesAsync()
    {
        SourceOperationState = "GitHub discovery выполняется…";
        SourceOperationState = await _sourceReview.DiscoverAsync(AppPathResolver.ResolveConfig(SourcesPath));
    }
    private async Task PreviewImportAsync()
    {
        SourceOperationState = await _sourceReview.PreviewImportAsync(AppPathResolver.ResolveConfig(SourcesPath));
    }
    private void Apply(DesktopSettings settings)
    {
        Theme = settings.Theme; OutputDirectory = settings.OutputDirectory; SourcesPath = settings.SourcesPath;
        DefaultCandidates = settings.QuickScan.MaximumCandidates; AutoOpenResults = settings.AutoOpenResults;
        Concurrency = settings.QuickScan.Concurrency; TimeoutSeconds = settings.QuickScan.TimeoutSeconds;
        AllowUnknownGeo = settings.QuickScan.AllowUnknownGeo; StabilityAttempts = settings.QuickScan.StabilityAttempts;
        RejectLikelyRussia = settings.RejectLikelyRussia; MinimumGeoConfidence = settings.MinimumGeoConfidence.ToString();
        BrowserLimit = settings.QuickScan.BrowserLimit; BrowserTimeoutSeconds = settings.BrowserTimeoutSeconds;
        CaptureScreenshots = settings.CaptureScreenshotsOnFailure; CountryDatabasePath = settings.CountryDatabasePath; AsnDatabasePath = settings.AsnDatabasePath;
        VideoUrls.Clear(); foreach (var url in settings.TestVideoUrls) VideoUrls.Add(url);
    }
}
