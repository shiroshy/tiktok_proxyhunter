using System.Collections.ObjectModel;
using System.Reflection;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Desktop.Services;

namespace TikTokProxyHunter.Desktop.ViewModels;

public sealed partial class DiagnosticsViewModel : ObservableObject
{
    private readonly IBrowserDoctor _browser; private readonly ILocalGeoIpProvider _geo; private readonly IExitIpProviderDiagnostics _exit;
    private readonly IProxySourceLoader _sources; private readonly IDesktopSettingsService _settings; private readonly DesktopLogStore _logs;
    private readonly IClipboardService _clipboard;
    private readonly IUiDispatcher _dispatcher;
    private int _logRefreshScheduled;
    public DiagnosticsViewModel(IBrowserDoctor browser, ILocalGeoIpProvider geo, IExitIpProviderDiagnostics exit,
        IProxySourceLoader sources, IDesktopSettingsService settings, DesktopLogStore logs, IClipboardService clipboard,
        IUiDispatcher dispatcher)
    {
        _browser = browser; _geo = geo; _exit = exit; _sources = sources; _settings = settings; _logs = logs; _clipboard = clipboard; _dispatcher = dispatcher;
        Components = []; LogLines = []; RefreshCommand = new AsyncRelayCommand(RefreshAsync);
        CopyReportCommand = new RelayCommand(() => _clipboard.CopyText(BuildReport()));
        ShowDebugCommand = new RelayCommand(() => { IncludeDebug = !IncludeDebug; RefreshLogs(); });
        logs.Changed += (_, _) => ScheduleLogRefresh();
    }
    public ObservableCollection<Models.RuntimeComponentState> Components { get; }
    public ObservableCollection<string> LogLines { get; }
    public IAsyncRelayCommand RefreshCommand { get; }
    public IRelayCommand CopyReportCommand { get; }
    public IRelayCommand ShowDebugCommand { get; }
    [ObservableProperty] private bool includeDebug;
    [ObservableProperty] private string applicationVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "unknown";
    [ObservableProperty] private string runtimeVersion = Environment.Version.ToString();
    [ObservableProperty] private string applicationPath = AppContext.BaseDirectory;
    [ObservableProperty] private string outputPath = string.Empty;
    [ObservableProperty] private int enabledSources;
    public async Task RefreshAsync()
    {
        var settings = (await _settings.LoadAsync()).Settings; OutputPath = settings.OutputDirectory;
        var doctor = await _browser.DiagnoseAsync(CancellationToken.None); var geo = await _geo.ValidateAsync(CancellationToken.None);
        var exitAttempts = await _exit.TestDirectAsync(CancellationToken.None); var sourceValues = await _sources.LoadDefinitionsAsync(AppPathResolver.ResolveConfig(settings.SourcesPath), CancellationToken.None);
        EnabledSources = sourceValues.Count(x => x.Enabled); Components.Clear();
        Components.Add(new("Chromium", doctor.LaunchSucceeded, doctor.LaunchSucceeded ? "Готов" : "Недоступен", doctor.Reason));
        Components.Add(new("GeoIP MMDB", geo.Any(x => x.Success), geo.Any(x => x.Success) ? "Готова" : "Не настроена", string.Join("; ", geo.Select(x => x.Reason))));
        foreach (var attempt in exitAttempts) Components.Add(new($"Exit IP: {attempt.Provider}", attempt.Status == ExitIpStatus.Resolved, attempt.Status.ToString(), attempt.Reason));
        Components.Add(new("Конфигурация источников", File.Exists(AppPathResolver.ResolveConfig(settings.SourcesPath)), $"Включено {EnabledSources}", null));
        RefreshLogs();
    }
    private void RefreshLogs()
    {
        var values = _logs.Snapshot(IncludeDebug ? LogLevel.Debug : LogLevel.Information).TakeLast(2_000).ToArray();
        LogLines.Clear(); foreach (var value in values) LogLines.Add($"{value.Timestamp:HH:mm:ss} {value.Level,-11} {value.Message}");
    }
    private void ScheduleLogRefresh()
    {
        if (Interlocked.Exchange(ref _logRefreshScheduled, 1) != 0) return;
        _ = Task.Delay(200).ContinueWith(_ => _dispatcher.Post(() =>
        {
            try { RefreshLogs(); }
            finally { Interlocked.Exchange(ref _logRefreshScheduled, 0); }
        }), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }
    private string BuildReport()
    {
        var builder = new StringBuilder(); builder.AppendLine($"TikTokProxyHunter {ApplicationVersion}"); builder.AppendLine($".NET {RuntimeVersion}");
        builder.AppendLine($"App: {ApplicationPath}"); builder.AppendLine($"Output: {OutputPath}"); builder.AppendLine($"Sources enabled: {EnabledSources}");
        foreach (var component in Components) builder.AppendLine($"{component.Name}: {component.Status} {component.Detail}"); return builder.ToString();
    }
}
