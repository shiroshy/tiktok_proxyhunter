using System.Windows;
using TikTokProxyHunter.Desktop.ViewModels;

namespace TikTokProxyHunter.Desktop.Views;

public partial class OnboardingWindow : Window
{
    public OnboardingWindow() => InitializeComponent();
    protected override async void OnContentRendered(EventArgs e) { base.OnContentRendered(e); if (DataContext is OnboardingViewModel vm) await vm.CheckAsync(); }
    private void Finish_Click(object sender, RoutedEventArgs e) { DialogResult = true; Close(); }
}
