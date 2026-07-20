using System.Windows.Controls;
using TikTokProxyHunter.Desktop.ViewModels;
namespace TikTokProxyHunter.Desktop.Views;
public partial class DashboardView : UserControl { public DashboardView() { InitializeComponent(); Loaded += async (_, _) => { if (DataContext is DashboardViewModel vm) await vm.InitializeAsync(); }; } }
