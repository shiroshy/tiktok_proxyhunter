using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Desktop.Services;

namespace TikTokProxyHunter.Desktop.ViewModels;

public sealed partial class OnboardingViewModel : ObservableObject
{
    private readonly IBrowserDoctor _browserDoctor;
    private readonly IDesktopSettingsService _settings;
    private readonly IChromiumInstaller _installer;

    public OnboardingViewModel(IBrowserDoctor browserDoctor, IDesktopSettingsService settings, IChromiumInstaller installer)
    {
        _browserDoctor = browserDoctor; _settings = settings; _installer = installer;
        NextCommand = new RelayCommand(() => Page++, () => Page < 2);
        PreviousCommand = new RelayCommand(() => Page--, () => Page > 0);
        InstallChromiumCommand = new AsyncRelayCommand(InstallChromiumAsync, () => !IsBusy);
    }

    [ObservableProperty] private int page;
    [ObservableProperty] private bool isBusy;
    [ObservableProperty] private string chromiumState = "Проверка…";
    [ObservableProperty] private string environmentState = string.Empty;
    public IRelayCommand NextCommand { get; }
    public IRelayCommand PreviousCommand { get; }
    public IAsyncRelayCommand InstallChromiumCommand { get; }
    partial void OnPageChanged(int value) { NextCommand.NotifyCanExecuteChanged(); PreviousCommand.NotifyCanExecuteChanged(); }

    public async Task CheckAsync()
    {
        var loaded = await _settings.LoadAsync();
        var result = await _browserDoctor.DiagnoseAsync(CancellationToken.None);
        ChromiumState = result.LaunchSucceeded ? "Установлен и запускается" : "Не установлен";
        EnvironmentState = $"Папка результатов: {(Directory.Exists(loaded.Settings.OutputDirectory) ? "готова" : "будет создана")}\n" +
                           $"Конфигурация источников: {(File.Exists(AppPathResolver.ResolveConfig(loaded.Settings.SourcesPath)) ? "найдена" : "не найдена")}\n" +
                           "GeoIP MMDB: необязательно";
    }

    private async Task InstallChromiumAsync()
    {
        IsBusy = true; InstallChromiumCommand.NotifyCanExecuteChanged();
        try { var result = await _installer.InstallAsync(null, CancellationToken.None); ChromiumState = result.Success ? "Установлен" : result.Message; }
        finally { IsBusy = false; InstallChromiumCommand.NotifyCanExecuteChanged(); }
    }
}
