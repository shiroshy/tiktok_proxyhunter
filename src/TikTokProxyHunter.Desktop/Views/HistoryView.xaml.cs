using System.Windows.Controls;
using TikTokProxyHunter.Desktop.ViewModels;
namespace TikTokProxyHunter.Desktop.Views;
public partial class HistoryView : UserControl { public HistoryView() { InitializeComponent(); Loaded += async (_, _) => { if (DataContext is HistoryViewModel vm) await vm.LoadAsync(); }; } }
