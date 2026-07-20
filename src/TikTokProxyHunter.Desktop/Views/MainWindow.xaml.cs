using System.ComponentModel;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Desktop.ViewModels;

namespace TikTokProxyHunter.Desktop.Views;

public partial class MainWindow : Window
{
    private bool _closingAfterCancellation;
    public MainWindow() { InitializeComponent(); Loaded += OnLoaded; Closing += OnClosing; }
    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (DataContext is not MainWindowViewModel vm) return;
        await vm.InitializeAsync(); var settings = vm.Settings;
        Width = Math.Clamp(settings.WindowWidth, MinWidth, SystemParameters.VirtualScreenWidth);
        Height = Math.Clamp(settings.WindowHeight, MinHeight, SystemParameters.VirtualScreenHeight);
        if (settings.WindowLeft is { } left && settings.WindowTop is { } top)
        {
            Left = Math.Clamp(left, SystemParameters.VirtualScreenLeft, SystemParameters.VirtualScreenLeft + SystemParameters.VirtualScreenWidth - Width);
            Top = Math.Clamp(top, SystemParameters.VirtualScreenTop, SystemParameters.VirtualScreenTop + SystemParameters.VirtualScreenHeight - Height);
        }
    }
    private async void OnClosing(object? sender, CancelEventArgs e)
    {
        if (_closingAfterCancellation) return;
        if (DataContext is not MainWindowViewModel vm) return;
        var controller = ((App)Application.Current).Services.GetRequiredService<IHunterRunController>();
        if (controller.IsRunActive) { e.Cancel = true; await controller.CancelAsync(); _closingAfterCancellation = true; await vm.SaveWindowStateAsync(Left, Top, Width, Height); Close(); return; }
        await vm.SaveWindowStateAsync(Left, Top, Width, Height);
    }
}
