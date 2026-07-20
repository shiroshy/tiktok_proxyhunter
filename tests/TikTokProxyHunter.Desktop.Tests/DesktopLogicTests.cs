using System.Diagnostics;
using System.IO;
using System.Windows.Threading;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Desktop;
using TikTokProxyHunter.Desktop.Models;
using TikTokProxyHunter.Desktop.Services;
using TikTokProxyHunter.Desktop.ViewModels;
using TikTokProxyHunter.Desktop.Views;
using TikTokProxyHunter.Infrastructure;

namespace TikTokProxyHunter.Desktop.Tests;

public sealed class DesktopLogicTests
{
    [Fact]
    public void Navigation_resolves_registered_pages()
    {
        var navigation = new NavigationService(); var dashboard = new object();
        navigation.Register("Dashboard", () => dashboard); navigation.Navigate("Dashboard");
        Assert.Same(dashboard, navigation.CurrentViewModel);
    }

    [Fact]
    public void Quick_scan_rejects_browser_without_video()
    {
        var configuration = new UiRunConfiguration { BrowserVerification = true, CheckPublicVideo = false };
        Assert.Contains(configuration.Validate(), x => x.Contains("видео", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(0)] [InlineData(250001)]
    public void Quick_scan_rejects_unsafe_candidate_limits(int limit) =>
        Assert.NotEmpty(new UiRunConfiguration { MaximumCandidates = limit }.Validate());

    [Fact]
    public async Task Run_controller_supports_start_and_cooperative_cancel()
    {
        var controller = new HunterRunController(new CancellableRunService());
        var task = controller.StartAsync(new() { OutputDirectory = "test" }, new RecordingObserver());
        await Task.Delay(30); Assert.True(controller.IsRunActive); await controller.CancelAsync();
        Assert.Equal(HunterRunStatus.Cancelled, (await task).Summary.Status);
    }

    [Fact]
    public void Resume_requires_checkpoint_and_private_state()
    {
        using var temp = TempDirectory.Create();
        var item = HistoryItem(temp.Path, HunterRunStatus.Cancelled); Assert.False(item.CanResume);
        File.WriteAllText(Path.Combine(temp.Path, "run-checkpoint.json"), "{}");
        File.WriteAllText(Path.Combine(temp.Path, "run-state.private.json"), "[]"); Assert.True(item.CanResume);
    }

    [Fact]
    public void Progress_aggregation_is_structured_and_deterministic()
    {
        var aggregator = new PipelineProgressAggregator();
        aggregator.Apply(Progress(HunterUiStage.ProbingProtocols, 80, 100, 12));
        Assert.Equal(12, aggregator.State.ProtocolAlive);
        Assert.Equal(HunterStageStatus.Running, aggregator.Stages.Single(x => x.Stage == HunterUiStage.ProbingProtocols).Status);
    }

    [Fact]
    public async Task Progress_sink_throttles_bursts()
    {
        var observer = new RecordingObserver(); var sink = new HunterProgressSink(observer, TimeSpan.FromMinutes(1));
        await sink.PublishAsync(Progress(HunterUiStage.CheckingHttps, 1, 10, 1), default);
        await sink.PublishAsync(Progress(HunterUiStage.CheckingHttps, 2, 10, 2), default);
        Assert.Single(observer.Values);
    }

    [Fact]
    public void Statuses_are_localized_for_users()
    {
        Assert.Equal("Рекомендован", StatusText.Recommendation(ProxyRecommendationClass.Recommended));
        Assert.DoesNotContain(nameof(TikTokCapabilityStatus.NotConfigured), StatusText.Capability(TikTokCapabilityStatus.NotConfigured));
    }

    [Fact]
    public void Results_filter_credentials_and_search_text()
    {
        var safe = Item("1.1.1.1:80", 80, false); var secret = Item("2.2.2.2:80", 90, true);
        var result = ProxyResultQuery.Apply([safe, secret], "Все", "Все", "", "1.1", 0, true).ToArray();
        Assert.Single(result); Assert.Same(safe, result[0]);
    }

    [Fact]
    public void Results_sort_by_quality_then_score()
    {
        var low = Item("1.1.1.1:80", 99, false, ProxyRecommendationClass.PageOnly);
        var high = Item("2.2.2.2:80", 50, false, ProxyRecommendationClass.Recommended);
        Assert.Equal(high, ProxyResultQuery.Apply([low, high], "Все", "Все", "", "", 0, false).First());
    }

    [Fact]
    public void Proxy_item_never_formats_credentials_into_clipboard_url()
    {
        var endpoint = Endpoint("host.example", 1080) with { Username = "alice", Password = "secret" };
        var item = ProxyResultItem.From(new ProxyCheckResult { Endpoint = endpoint, Score = new(1, []) });
        Assert.Equal("socks5://host.example:1080", item.ProxyUrl); Assert.True(item.HasCredentials);
        Assert.Null(item.Detail!.Endpoint.Password); Assert.Null(item.Detail.Endpoint.Username);
    }

    [Fact]
    public async Task Source_toggle_is_written_atomically()
    {
        using var temp = TempDirectory.Create(); var path = Path.Combine(temp.Path, "sources.json");
        var source = new ProxySourceDefinition { Name = "local", Enabled = true, Path = "sample.txt" };
        var catalog = new SourceCatalogService(new FakeSourceLoader([source])); await catalog.SetEnabledAsync(path, "local", false);
        var values = JsonSerializer.Deserialize<List<ProxySourceDefinition>>(await File.ReadAllTextAsync(path), JsonDefaults.Options);
        Assert.False(Assert.Single(values!).Enabled); Assert.Empty(Directory.GetFiles(temp.Path, "*.tmp"));
    }

    [Fact]
    public async Task Settings_save_is_atomic_and_persists_theme()
    {
        using var temp = TempDirectory.Create(); var path = Path.Combine(temp.Path, "settings.json"); var service = new DesktopSettingsService(path);
        await service.SaveAsync(new DesktopSettings { Theme = DesktopTheme.Light, OnboardingCompleted = true });
        var loaded = await service.LoadAsync(); Assert.Equal(DesktopTheme.Light, loaded.Settings.Theme); Assert.True(loaded.Settings.OnboardingCompleted);
    }

    [Fact]
    public async Task Corrupt_settings_are_backed_up_and_recovered()
    {
        using var temp = TempDirectory.Create(); var path = Path.Combine(temp.Path, "settings.json"); await File.WriteAllTextAsync(path, "{broken");
        var result = await new DesktopSettingsService(path).LoadAsync();
        Assert.NotNull(result.Warning); Assert.NotNull(result.CorruptBackupPath); Assert.True(File.Exists(result.CorruptBackupPath));
    }

    [Fact]
    public async Task History_accepts_only_valid_manifests()
    {
        using var temp = TempDirectory.Create(); var invalid = Directory.CreateDirectory(Path.Combine(temp.Path, "random"));
        await File.WriteAllTextAsync(Path.Combine(invalid.FullName, "summary.json"), "{}");
        Assert.Empty(await new RunHistoryService().LoadAsync(temp.Path));
    }

    [Fact]
    public void Explain_presentation_redacts_credentials()
    {
        var item = ProxyResultItem.From(new ProxyCheckResult { Endpoint = Endpoint("proxy.test", 8080) with { Username = "user", Password = "pass" }, Score = new(0, []) });
        Assert.DoesNotContain("pass", item.ProxyUrl, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("user@", item.ProxyUrl, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Runtime_component_states_represent_optional_browser_and_mmdb()
    {
        var browser = new RuntimeComponentState("Chromium", false, "Не установлен");
        var mmdb = new RuntimeComponentState("GeoIP MMDB", false, "Не настроена");
        Assert.False(browser.Available); Assert.False(mmdb.Available);
    }

    [Fact]
    public void Error_presentation_is_actionable_and_hides_stack_trace()
    {
        var ui = ErrorPresentation.From(new() { UserMessage = "Provider временно недоступен", TechnicalType = "HttpRequestException", TechnicalMessage = "trace", Stage = HunterUiStage.ResolvingExitIp });
        Assert.NotEmpty(ui.Suggestions); Assert.DoesNotContain(" at ", ui.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void User_safe_selection_excludes_credentials()
    {
        var values = ProxyResultQuery.Apply([Item("1:1", 1, false), Item("2:2", 2, true)], "Все", "Все", "", "", 0, true);
        Assert.All(values, x => Assert.False(x.HasCredentials));
    }

    [Fact]
    public void Desktop_log_redacts_proxy_passwords()
    {
        var store = new DesktopLogStore(); var logger = store.CreateLogger("test");
        logger.Log(Microsoft.Extensions.Logging.LogLevel.Error, default, "http://user:secret@proxy.test:80", null, (state, _) => state);
        Assert.DoesNotContain("secret", Assert.Single(store.Snapshot()).Message, StringComparison.Ordinal);
    }

    private static HunterRunProgress Progress(HunterUiStage stage, long processed, long total, long passed) => new()
    { RunId = Guid.NewGuid(), Event = HunterProgressEvent.StageProgress, Status = HunterRunStatus.Running,
      Stage = new() { Stage = stage, Status = HunterStageStatus.Running, Processed = processed, Total = total, Passed = passed } };
    private static ProxyEndpoint Endpoint(string host, int port) => new() { Host = host, Port = port, Source = "test", NormalizedKey = $"{host}:{port}:socks5", DetectedProtocol = ProxyProtocol.Socks5, Sources = ["test"], SourceFamilies = ["family"] };
    private static ProxyResultItem Item(string address, int score, bool credentials, ProxyRecommendationClass quality = ProxyRecommendationClass.PageOnly) => new()
    { Key = address, Address = address, ProxyUrl = "http://" + address, Protocol = "HTTP CONNECT", Country = "KZ", TikTokStatus = "Пройдено", VideoStatus = "Не проверялось", Stability = "2/3", Score = score, RecommendationClass = quality, HasCredentials = credentials };
    private static RunHistoryItem HistoryItem(string path, HunterRunStatus status)
    {
        var summary = new HunterRunSummary { RunId = Guid.NewGuid(), Status = status, OutputDirectory = path };
        return new() { Directory = path, Manifest = new() { RunId = summary.RunId, Configuration = new() { OutputDirectory = path }, Summary = summary } };
    }
    private sealed class RecordingObserver : IHunterRunObserver
    { public List<HunterRunProgress> Values { get; } = []; public ValueTask OnProgressAsync(HunterRunProgress progress, CancellationToken cancellationToken) { Values.Add(progress); return ValueTask.CompletedTask; } }
    private sealed class CancellableRunService : IHunterRunService
    {
        public async Task<HunterRunResult> RunAsync(HunterRunConfiguration configuration, IHunterRunObserver observer, CancellationToken cancellationToken)
        { try { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); throw new InvalidOperationException(); } catch (OperationCanceledException) { return new() { Summary = new() { Status = HunterRunStatus.Cancelled, OutputDirectory = configuration.OutputDirectory } }; } }
    }
    private sealed class FakeSourceLoader(IReadOnlyList<ProxySourceDefinition> values) : IProxySourceLoader
    { public Task<IReadOnlyList<ProxySourceDefinition>> LoadDefinitionsAsync(string path, CancellationToken cancellationToken) => Task.FromResult(values); public Task<IReadOnlyList<ProxySourceResult>> LoadEnabledAsync(IEnumerable<ProxySourceDefinition> definitions, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<ProxySourceResult>>([]); }
    private sealed class TempDirectory : IDisposable
    {
        public required string Path { get; init; }
        public static TempDirectory Create() { var path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "TikTokProxyHunter.Tests", Guid.NewGuid().ToString("N")); Directory.CreateDirectory(path); return new() { Path = path }; }
        public void Dispose() { if (Directory.Exists(Path)) Directory.Delete(Path, true); }
    }
}

[CollectionDefinition("Wpf smoke", DisableParallelization = true)]
public sealed class WpfSmokeCollection;

[Collection("Wpf smoke")]
public sealed class DesktopSmokeTests
{
    [Fact]
    public void Host_resolves_and_renders_main_window_without_critical_binding_errors()
    {
        Exception? failure = null; string trace = string.Empty;
        var thread = new Thread(() =>
        {
            try
            {
                var writer = new StringWriter(); var listener = new TextWriterTraceListener(writer);
                PresentationTraceSources.DataBindingSource.Listeners.Add(listener); PresentationTraceSources.DataBindingSource.Switch.Level = SourceLevels.Error;
                var app = new App(); app.InitializeComponent(); using var host = App.BuildHost();
                var viewModels = new[] { typeof(MainWindowViewModel), typeof(DashboardViewModel), typeof(ScanViewModel), typeof(ResultsViewModel), typeof(SourcesViewModel), typeof(HistoryViewModel), typeof(SettingsViewModel), typeof(DiagnosticsViewModel) };
                foreach (var type in viewModels) Assert.NotNull(host.Services.GetRequiredService(type));
                var sample = new ProxyCheckResult { Endpoint = new() { Host = "203.0.113.10", Port = 8080, Source = "smoke", NormalizedKey = "203.0.113.10:8080:http", DetectedProtocol = ProxyProtocol.HttpsConnect, Sources = ["smoke"], SourceFamilies = ["smoke"] }, Score = new(42, []) };
                host.Services.GetRequiredService<DesktopSession>().SetRun(new() { Summary = new() { RunId = Guid.NewGuid(), Status = HunterRunStatus.Completed, StartedAt = DateTimeOffset.UtcNow, OutputDirectory = Path.GetTempPath() }, Results = [sample] });
                host.Services.GetRequiredService<ProxyDetailsViewModel>().SetResult(ProxyResultItem.From(sample));
                var window = host.Services.GetRequiredService<MainWindow>(); window.Show();
                var navigation = host.Services.GetRequiredService<INavigationService>();
                foreach (var page in new[] { "Dashboard", "Results", "ProxyDetails", "Sources", "History", "Settings" })
                { navigation.Navigate(page); window.UpdateLayout(); }
                window.Close();
                listener.Flush(); trace = writer.ToString(); PresentationTraceSources.DataBindingSource.Listeners.Remove(listener); app.Shutdown();
            }
            catch (Exception ex) { failure = ex; }
        });
        thread.SetApartmentState(ApartmentState.STA); thread.Start(); Assert.True(thread.Join(TimeSpan.FromSeconds(20)));
        Assert.Null(failure); Assert.DoesNotContain("System.Windows.Data Error", trace, StringComparison.Ordinal);
    }
}
