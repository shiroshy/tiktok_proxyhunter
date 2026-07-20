using System.Windows;
using TikTokProxyHunter.Desktop.Models;
using TikTokProxyHunter.Desktop.ViewModels;
using TikTokProxyHunter.Desktop.Views;

namespace TikTokProxyHunter.Desktop.Services;

public sealed class QuickScanDialogService(INavigationService navigation) : IQuickScanDialogService
{
    public Task<UiRunConfiguration?> ShowAsync(UiRunConfiguration initial)
    {
        var viewModel = new QuickScanViewModel(initial);
        var window = new QuickScanWindow
        {
            DataContext = viewModel,
            Owner = Application.Current?.MainWindow
        };
        var accepted = window.ShowDialog() == true;
        if (!accepted && window.AdvancedRequested) navigation.Navigate("Settings");
        return Task.FromResult(accepted ? viewModel.Configuration : null);
    }
}
