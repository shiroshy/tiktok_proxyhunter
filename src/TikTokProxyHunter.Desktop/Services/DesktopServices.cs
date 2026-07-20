using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Windows;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Desktop.Models;
using TikTokProxyHunter.Infrastructure;

namespace TikTokProxyHunter.Desktop.Services;

public interface INavigationService
{
    object? CurrentViewModel { get; }
    event EventHandler<object>? Navigated;
    void Register(string key, Func<object> factory);
    void Navigate(string key);
}

public sealed class NavigationService : INavigationService
{
    private readonly Dictionary<string, Func<object>> _factories = new(StringComparer.OrdinalIgnoreCase);
    public object? CurrentViewModel { get; private set; }
    public event EventHandler<object>? Navigated;
    public void Register(string key, Func<object> factory) => _factories[key] = factory;
    public void Navigate(string key)
    {
        if (!_factories.TryGetValue(key, out var factory)) throw new KeyNotFoundException($"Unknown page '{key}'.");
        CurrentViewModel = factory(); Navigated?.Invoke(this, CurrentViewModel);
    }
}

public interface IDialogService
{
    Task<bool> ConfirmAsync(string title, string message);
    Task ShowErrorAsync(UiErrorPresentation error);
    Task ShowInformationAsync(string title, string message);
}

public interface IQuickScanDialogService
{
    Task<UiRunConfiguration?> ShowAsync(UiRunConfiguration initial);
}

public sealed class DialogService : IDialogService
{
    public Task<bool> ConfirmAsync(string title, string message) => Task.FromResult(
        MessageBox.Show(message, title, MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes);
    public Task ShowErrorAsync(UiErrorPresentation error)
    {
        var suggestions = error.Suggestions.Count == 0 ? string.Empty : "\n\nЧто можно сделать:\n• " + string.Join("\n• ", error.Suggestions);
        MessageBox.Show(error.Reason + suggestions, error.Title, MessageBoxButton.OK, MessageBoxImage.Error); return Task.CompletedTask;
    }
    public Task ShowInformationAsync(string title, string message)
    { MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Information); return Task.CompletedTask; }
}

public interface IClipboardService
{
    Task<bool> CopyProxyUrlAsync(ProxyResultItem item);
    void CopyText(string text);
}

public sealed class ClipboardService(IDialogService dialogs) : IClipboardService
{
    private bool _warningAccepted;
    public async Task<bool> CopyProxyUrlAsync(ProxyResultItem item)
    {
        if (item.HasCredentials) return false;
        if (!_warningAccepted)
        {
            _warningAccepted = await dialogs.ConfirmAsync("Небезопасный публичный прокси",
                "Не вводите через непроверенный публичный прокси пароли, токены или платёжные данные.\n\nСкопировать адрес?");
            if (!_warningAccepted) return false;
        }
        Clipboard.SetText(item.ProxyUrl); return true;
    }
    public void CopyText(string text) => Clipboard.SetText(text);
}

public interface IFilePickerService
{
    string? PickJson(string title);
    string? PickMmdb(string title);
}

public sealed class FilePickerService : IFilePickerService
{
    public string? PickJson(string title) => Pick(title, "JSON (*.json)|*.json|Все файлы (*.*)|*.*");
    public string? PickMmdb(string title) => Pick(title, "GeoIP MMDB (*.mmdb)|*.mmdb|Все файлы (*.*)|*.*");
    private static string? Pick(string title, string filter)
    { var dialog = new OpenFileDialog { Title = title, Filter = filter, CheckFileExists = true }; return dialog.ShowDialog() == true ? dialog.FileName : null; }
}

public sealed record SettingsLoadResult(DesktopSettings Settings, string? Warning, string? CorruptBackupPath);

public interface IDesktopSettingsService
{
    string SettingsPath { get; }
    Task<SettingsLoadResult> LoadAsync(CancellationToken token = default);
    Task SaveAsync(DesktopSettings settings, CancellationToken token = default);
}

public sealed class DesktopSettingsService(string? path = null, ILogger<DesktopSettingsService>? logger = null) : IDesktopSettingsService
{
    public string SettingsPath { get; } = path ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "TikTokProxyHunter", "desktop-settings.json");
    public async Task<SettingsLoadResult> LoadAsync(CancellationToken token = default)
    {
        if (!File.Exists(SettingsPath)) return new(new DesktopSettings(), null, null);
        try
        {
            await using var stream = File.OpenRead(SettingsPath);
            var settings = await JsonSerializer.DeserializeAsync<DesktopSettings>(stream, JsonDefaults.Options, token);
            return new(settings ?? new DesktopSettings(), settings is null ? "Настройки были пустыми и восстановлены." : null, null);
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            logger?.LogWarning(ex, "Desktop settings at {Path} are invalid; safe defaults will be restored", SettingsPath);
            var backup = SettingsPath + ".corrupt-" + DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmss") + ".bak";
            try { File.Move(SettingsPath, backup, true); }
            catch (IOException backupError) { logger?.LogWarning(backupError, "Unable to preserve corrupt settings backup at {Backup}", backup); backup = null; }
            return new(new DesktopSettings(), "Файл настроек повреждён. Восстановлены безопасные значения.", backup);
        }
    }
    public Task SaveAsync(DesktopSettings settings, CancellationToken token = default) => AtomicJson.WriteAsync(SettingsPath, Sanitize(settings), token);
    public static DesktopSettings Sanitize(DesktopSettings settings) => settings with
    { TestVideoUrls = settings.TestVideoUrls.Select(SanitizeUrl).Where(x => x is not null).Cast<string>().ToArray() };
    private static string? SanitizeUrl(string value) => Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && TikTokVideoUrlParser.TryParse(uri, ["tiktok.com"], out _, out _, out _) ? uri.GetLeftPart(UriPartial.Path) : null;
}

public interface IRunHistoryService
{
    Task<IReadOnlyList<RunHistoryItem>> LoadAsync(string outputRoot, CancellationToken token = default);
    Task DeleteAsync(RunHistoryItem item, string expectedOutputRoot, CancellationToken token = default);
}

public sealed class RunHistoryService(ILogger<RunHistoryService>? logger = null) : IRunHistoryService
{
    public async Task<IReadOnlyList<RunHistoryItem>> LoadAsync(string outputRoot, CancellationToken token = default)
    {
        var root = Path.GetFullPath(outputRoot); if (!Directory.Exists(root)) return [];
        var result = new List<RunHistoryItem>();
        foreach (var manifestPath in Directory.EnumerateFiles(root, "run-manifest.json", SearchOption.AllDirectories))
        {
            token.ThrowIfCancellationRequested();
            try
            {
                await using var stream = File.OpenRead(manifestPath);
                var manifest = await JsonSerializer.DeserializeAsync<HunterRunManifest>(stream, JsonDefaults.Options, token);
                if (manifest is null || manifest.SchemaVersion != 1 || manifest.RunId == Guid.Empty
                    || string.IsNullOrWhiteSpace(manifest.Summary.OutputDirectory)) continue;
                var directory = Path.GetDirectoryName(manifestPath)!;
                if (!Path.GetFullPath(manifest.Summary.OutputDirectory).Equals(Path.GetFullPath(directory), StringComparison.OrdinalIgnoreCase)) continue;
                result.Add(new() { Directory = directory, Manifest = manifest });
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
            { logger?.LogWarning(ex, "Ignoring invalid run manifest at {Path}", manifestPath); }
        }
        return result.OrderByDescending(x => x.StartedAt).ToArray();
    }
    public Task DeleteAsync(RunHistoryItem item, string expectedOutputRoot, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested(); var root = EnsureTrailingSeparator(Path.GetFullPath(expectedOutputRoot));
        var target = Path.GetFullPath(item.Directory);
        if (!EnsureTrailingSeparator(target).StartsWith(root, StringComparison.OrdinalIgnoreCase)
            || !File.Exists(Path.Combine(target, "run-manifest.json"))) throw new InvalidOperationException("Run directory is outside the configured output root.");
        Directory.Delete(target, true); return Task.CompletedTask;
    }
    private static string EnsureTrailingSeparator(string value) => value.EndsWith(Path.DirectorySeparatorChar) ? value : value + Path.DirectorySeparatorChar;
}

public interface ISourceCatalogService
{
    Task<IReadOnlyList<ProxySourceDefinition>> LoadAsync(string path, CancellationToken token = default);
    Task SetEnabledAsync(string path, string sourceName, bool enabled, CancellationToken token = default);
}

public sealed class SourceCatalogService(IProxySourceLoader loader) : ISourceCatalogService
{
    public Task<IReadOnlyList<ProxySourceDefinition>> LoadAsync(string path, CancellationToken token = default) => loader.LoadDefinitionsAsync(path, token);
    public async Task SetEnabledAsync(string path, string sourceName, bool enabled, CancellationToken token = default)
    {
        var definitions = (await loader.LoadDefinitionsAsync(path, token)).ToList();
        var index = definitions.FindIndex(x => x.Name.Equals(sourceName, StringComparison.OrdinalIgnoreCase));
        if (index < 0) throw new KeyNotFoundException(sourceName);
        definitions[index] = definitions[index] with { Enabled = enabled };
        await AtomicJson.WriteAsync(path, definitions, token);
    }
}

public interface ISourceReviewService
{
    Task<string> DiscoverAsync(string sourceCatalogPath, CancellationToken token = default);
    Task<string> PreviewImportAsync(string sourceCatalogPath, CancellationToken token = default);
}

public sealed class SourceReviewService(IProxySourceLoader loader, IGitHubSourceDiscoveryService discovery) : ISourceReviewService
{
    public async Task<string> DiscoverAsync(string sourceCatalogPath, CancellationToken token = default)
    {
        var known = await loader.LoadDefinitionsAsync(sourceCatalogPath, token);
        var report = await discovery.DiscoverAsync(known, null, token);
        var directory = Path.GetDirectoryName(Path.GetFullPath(sourceCatalogPath))!;
        await AtomicJson.WriteAsync(Path.Combine(directory, "discovered-proxy-sources.json"), report.Sources, token);
        var accepted = report.Sources.Count(x => x.Status == SourceDiscoveryStatus.AcceptedForReview);
        return $"Проверено файлов: {report.Sources.Count}; принято для ручного просмотра: {accepted}. Новые источники не включены автоматически."
            + (report.StopReason is null ? string.Empty : $" Остановка: {report.StopReason}");
    }

    public async Task<string> PreviewImportAsync(string sourceCatalogPath, CancellationToken token = default)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(sourceCatalogPath))!;
        var discoveredPath = Path.Combine(directory, "discovered-proxy-sources.json");
        if (!File.Exists(discoveredPath)) return "Файл discovered-proxy-sources.json не найден. Сначала выполните discovery.";
        await using var stream = File.OpenRead(discoveredPath);
        var discovered = await JsonSerializer.DeserializeAsync<List<DiscoveredProxySource>>(stream, JsonDefaults.Options, token) ?? [];
        var current = await loader.LoadDefinitionsAsync(sourceCatalogPath, token);
        var names = current.Select(x => x.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var additions = discovered.Where(x => x.Status == SourceDiscoveryStatus.AcceptedForReview && !names.Contains(x.Definition.Name)).ToArray();
        return $"Dry-run diff: +{additions.Length} отключённых definitions. Основной каталог не изменён.";
    }
}

public interface IResultStore
{
    Task<IReadOnlyList<ProxyResultItem>> LoadSafeAsync(string runDirectory, int limit = 2_000, CancellationToken token = default);
    Task<IReadOnlyList<ProxySourceHealth>> LoadSourceHealthAsync(string runDirectory, CancellationToken token = default);
}

public sealed class ResultStore : IResultStore
{
    public async Task<IReadOnlyList<ProxyResultItem>> LoadSafeAsync(string runDirectory, int limit = 2_000, CancellationToken token = default)
    {
        var statePath = Path.Combine(runDirectory, "run-state.private.json"); if (!File.Exists(statePath)) return [];
        await using var stream = File.OpenRead(statePath);
        var values = await JsonSerializer.DeserializeAsync<List<ProxyCheckResult>>(stream, JsonDefaults.Options, token) ?? [];
        return values.OrderByDescending(x => ProxyResultQuery.QualityRank(x.RecommendationClass)).ThenByDescending(x => x.Score.Value)
            .Take(Math.Clamp(limit, 1, 10_000)).Select(ProxyResultItem.From).ToArray();
    }
    public async Task<IReadOnlyList<ProxySourceHealth>> LoadSourceHealthAsync(string runDirectory, CancellationToken token = default)
    {
        var path = Path.Combine(runDirectory, "sources-health.json"); if (!File.Exists(path)) return [];
        await using var stream = File.OpenRead(path);
        return await JsonSerializer.DeserializeAsync<List<ProxySourceHealth>>(stream, JsonDefaults.Options, token) ?? [];
    }
}

public interface INotificationService
{
    event EventHandler<string>? Notification;
    void Show(string message);
}

public sealed class NotificationService : INotificationService
{
    public event EventHandler<string>? Notification;
    public void Show(string message) => Notification?.Invoke(this, message);
}

public interface IUiDispatcher { void Post(Action action); }
public sealed class WpfUiDispatcher : IUiDispatcher
{
    public void Post(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess()) action(); else _ = dispatcher.BeginInvoke(action);
    }
}

public interface IThemeService { DesktopTheme Current { get; } void Apply(DesktopTheme theme); }
public sealed class ThemeService : IThemeService
{
    public DesktopTheme Current { get; private set; }
    public void Apply(DesktopTheme theme)
    {
        Current = theme; var effective = theme == DesktopTheme.System
            ? SystemParameters.HighContrast || !IsSystemLight() ? DesktopTheme.Dark : DesktopTheme.Light : theme;
        var dictionaries = Application.Current?.Resources.MergedDictionaries; if (dictionaries is null) return;
        var existing = dictionaries.FirstOrDefault(x => x.Source?.OriginalString.Contains("Theme.xaml", StringComparison.OrdinalIgnoreCase) == true);
        if (existing is not null) dictionaries.Remove(existing);
        dictionaries.Add(new ResourceDictionary { Source = new Uri($"Themes/{effective}Theme.xaml", UriKind.Relative) });
    }
    private static bool IsSystemLight()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
        return key?.GetValue("AppsUseLightTheme") is int value && value != 0;
    }
}

public interface IChromiumInstaller
{
    Task<(bool Success, string Message)> InstallAsync(IProgress<string>? progress, CancellationToken token);
}

public sealed class ChromiumInstaller : IChromiumInstaller
{
    public async Task<(bool Success, string Message)> InstallAsync(IProgress<string>? progress, CancellationToken token)
    {
        var script = Path.Combine(AppContext.BaseDirectory, "playwright.ps1");
        if (!File.Exists(script)) return (false, $"Скрипт Playwright не найден: {script}");
        var start = new ProcessStartInfo { FileName = "powershell.exe", UseShellExecute = false,
            RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        start.ArgumentList.Add("-NoProfile"); start.ArgumentList.Add("-ExecutionPolicy"); start.ArgumentList.Add("Bypass");
        start.ArgumentList.Add("-File"); start.ArgumentList.Add(script); start.ArgumentList.Add("install"); start.ArgumentList.Add("chromium");
        using var process = new Process { StartInfo = start, EnableRaisingEvents = true };
        process.OutputDataReceived += (_, e) => { if (!string.IsNullOrWhiteSpace(e.Data)) progress?.Report(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (!string.IsNullOrWhiteSpace(e.Data)) progress?.Report(e.Data); };
        if (!process.Start()) return (false, "Не удалось запустить установщик Chromium.");
        process.BeginOutputReadLine(); process.BeginErrorReadLine();
        await process.WaitForExitAsync(token);
        return process.ExitCode == 0 ? (true, "Chromium установлен.") : (false, $"Установщик завершился с кодом {process.ExitCode}.");
    }
}

public static class ErrorPresentation
{
    public static UiErrorPresentation From(HunterRunFailure failure) => new("Не удалось проверить прокси", failure.UserMessage,
        failure.Stage == HunterUiStage.ResolvingExitIp
            ? ["Повторить позже", "Проверить состояние exit-IP providers", "Продолжить без подтверждённой страны"]
            : ["Повторить операцию", "Открыть диагностику", "Проверить настройки сети"],
        $"{failure.TechnicalType}: {failure.TechnicalMessage}");
}

public static class AppPathResolver
{
    public static string ResolveConfig(string relativePath)
    {
        var basePath = Path.Combine(AppContext.BaseDirectory, relativePath); if (File.Exists(basePath)) return basePath;
        var current = Path.GetFullPath(relativePath); return current;
    }
}
