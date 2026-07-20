using System.Windows;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Desktop.Models;
using TikTokProxyHunter.Desktop.Services;
using TikTokProxyHunter.Desktop.ViewModels;
using TikTokProxyHunter.Desktop.Views;
using TikTokProxyHunter.Infrastructure;

namespace TikTokProxyHunter.Desktop;

public partial class App : Application
{
    private IHost? _host;
    public IServiceProvider Services => _host?.Services ?? throw new InvalidOperationException("Application host is not ready.");
    public App()
    {
        DispatcherUnhandledException += (_, eventArgs) =>
        {
            _host?.Services.GetService<Microsoft.Extensions.Logging.ILogger<App>>()?.LogError(eventArgs.Exception, "Unhandled desktop error");
            MessageBox.Show("Действие не удалось завершить. Откройте раздел «Диагностика» для подробностей.",
                "Ошибка TikTok Proxy Hunter", MessageBoxButton.OK, MessageBoxImage.Error);
            eventArgs.Handled = true;
        };
    }

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        _host = BuildHost(e.Args); await _host.StartAsync();
        var settingsService = Services.GetRequiredService<IDesktopSettingsService>();
        var loaded = await settingsService.LoadAsync();
        Services.GetRequiredService<IThemeService>().Apply(loaded.Settings.Theme);
        if (!loaded.Settings.OnboardingCompleted)
        {
            var onboarding = Services.GetRequiredService<OnboardingWindow>();
            if (onboarding.ShowDialog() == true)
                await settingsService.SaveAsync(loaded.Settings with { OnboardingCompleted = true });
        }
        var window = Services.GetRequiredService<MainWindow>(); MainWindow = window; window.Show();
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        if (_host is not null) { await _host.StopAsync(TimeSpan.FromSeconds(10)); _host.Dispose(); }
        base.OnExit(e);
    }

    internal static IHost BuildHost(string[]? args = null)
    {
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { Args = args ?? [], ContentRootPath = AppContext.BaseDirectory });
        builder.Configuration.AddJsonFile("appsettings.json", optional: false, reloadOnChange: false);
        var hunter = builder.Configuration.GetSection("Hunter").Get<HunterOptions>() ?? new();
        var geo = builder.Configuration.GetSection("Geo").Get<GeoOptions>() ?? new();
        var exitIp = builder.Configuration.GetSection("ExitIp").Get<ExitIpOptions>() ?? new();
        var tikTok = builder.Configuration.GetSection("TikTok").Get<TikTokVerificationOptions>() ?? new();
        var stability = builder.Configuration.GetSection("Stability").Get<StabilityOptions>() ?? new();
        var browser = builder.Configuration.GetSection("BrowserVerification").Get<BrowserVerificationOptions>() ?? new();
        var discovery = builder.Configuration.GetSection("GitHubDiscovery").Get<GitHubDiscoveryOptions>() ?? new();
        var limits = builder.Configuration.GetSection("PipelineLimits").Get<PipelineLimits>() ?? new();
        var preScore = builder.Configuration.GetSection("PreScore").Get<ProxyPreScoreWeights>() ?? new();
        var ttl = builder.Configuration.GetSection("ResultTtl").Get<ResultTtlOptions>() ?? new();
        builder.Logging.ClearProviders(); builder.Logging.SetMinimumLevel(LogLevel.Information);
        builder.Services.AddSingleton<DesktopLogStore>(); builder.Services.AddSingleton<ILoggerProvider>(sp => sp.GetRequiredService<DesktopLogStore>());
        builder.Services.AddProxyHunterInfrastructure(hunter, geo, exitIp, tikTok, stability, browser, discovery, limits, preScore, ttl);
        AddDesktopServices(builder.Services);
        return builder.Build();
    }

    private static void AddDesktopServices(IServiceCollection services)
    {
        services.AddSingleton<DesktopSession>(); services.AddSingleton<PipelineUiAdapter>();
        services.AddSingleton<INavigationService, NavigationService>(); services.AddSingleton<IDialogService, DialogService>();
        services.AddSingleton<IQuickScanDialogService, QuickScanDialogService>(); services.AddSingleton<IClipboardService, ClipboardService>();
        services.AddSingleton<IFilePickerService, FilePickerService>(); services.AddSingleton<IDesktopSettingsService, DesktopSettingsService>();
        services.AddSingleton<IRunHistoryService, RunHistoryService>(); services.AddSingleton<ISourceCatalogService, SourceCatalogService>();
        services.AddSingleton<ISourceReviewService, SourceReviewService>();
        services.AddSingleton<IResultStore, ResultStore>(); services.AddSingleton<INotificationService, NotificationService>();
        services.AddSingleton<IUiDispatcher, WpfUiDispatcher>(); services.AddSingleton<IThemeService, ThemeService>();
        services.AddSingleton<IChromiumInstaller, ChromiumInstaller>();
        services.AddSingleton<DashboardViewModel>(); services.AddSingleton<ScanViewModel>(); services.AddSingleton<ResultsViewModel>();
        services.AddSingleton<ProxyDetailsViewModel>(); services.AddSingleton<SourcesViewModel>(); services.AddSingleton<HistoryViewModel>();
        services.AddSingleton<SettingsViewModel>(); services.AddSingleton<DiagnosticsViewModel>(); services.AddTransient<OnboardingViewModel>();
        services.AddTransient<OnboardingWindow>(sp => new() { DataContext = sp.GetRequiredService<OnboardingViewModel>() });
        services.AddSingleton<MainWindowViewModel>(sp =>
        {
            var navigation = sp.GetRequiredService<INavigationService>();
            navigation.Register("Dashboard", () => sp.GetRequiredService<DashboardViewModel>());
            navigation.Register("Scan", () => sp.GetRequiredService<ScanViewModel>());
            navigation.Register("Results", () => sp.GetRequiredService<ResultsViewModel>());
            navigation.Register("ProxyDetails", () => sp.GetRequiredService<ProxyDetailsViewModel>());
            navigation.Register("Sources", () => sp.GetRequiredService<SourcesViewModel>());
            navigation.Register("History", () => sp.GetRequiredService<HistoryViewModel>());
            navigation.Register("Settings", () => sp.GetRequiredService<SettingsViewModel>());
            navigation.Register("Diagnostics", () => sp.GetRequiredService<DiagnosticsViewModel>());
            return new(navigation, sp.GetRequiredService<IDesktopSettingsService>(), sp.GetRequiredService<PipelineUiAdapter>(),
                sp.GetRequiredService<DashboardViewModel>(), sp.GetRequiredService<ResultsViewModel>(),
                sp.GetRequiredService<SourcesViewModel>(), sp.GetRequiredService<HistoryViewModel>(),
                sp.GetRequiredService<SettingsViewModel>(), sp.GetRequiredService<DiagnosticsViewModel>());
        });
        services.AddTransient<MainWindow>(sp => new() { DataContext = sp.GetRequiredService<MainWindowViewModel>() });
    }
}
