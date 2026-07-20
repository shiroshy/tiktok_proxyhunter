using System.Windows.Controls;
using TikTokProxyHunter.Desktop.ViewModels;
namespace TikTokProxyHunter.Desktop.Views;
public partial class DiagnosticsView : UserControl { public DiagnosticsView() { InitializeComponent(); Loaded += async (_, _) => { if (DataContext is DiagnosticsViewModel vm) await vm.RefreshAsync(); }; } }
