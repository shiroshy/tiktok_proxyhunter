using System.Windows.Controls;
using TikTokProxyHunter.Desktop.ViewModels;
namespace TikTokProxyHunter.Desktop.Views;
public partial class SourcesView : UserControl { public SourcesView() { InitializeComponent(); Loaded += async (_, _) => { if (DataContext is SourcesViewModel vm) await vm.LoadAsync(); }; } }
