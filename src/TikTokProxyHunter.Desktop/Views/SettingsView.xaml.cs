using System.Windows.Controls;
using TikTokProxyHunter.Desktop.ViewModels;
namespace TikTokProxyHunter.Desktop.Views;
public partial class SettingsView : UserControl { public SettingsView() { InitializeComponent(); Loaded += async (_, _) => { if (DataContext is SettingsViewModel vm) await vm.InitializeAsync(); }; } }
