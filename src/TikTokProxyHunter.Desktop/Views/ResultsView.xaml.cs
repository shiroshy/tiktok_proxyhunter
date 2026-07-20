using System.Windows;
using System.Windows.Controls;
using TikTokProxyHunter.Desktop.ViewModels;
namespace TikTokProxyHunter.Desktop.Views;
public partial class ResultsView : UserControl { public ResultsView() { InitializeComponent(); Loaded += async (_, _) => { if (DataContext is ResultsViewModel vm) await vm.InitializeAsync(); }; } private void Grid_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e) { if (DataContext is ResultsViewModel vm && vm.OpenDetailsCommand.CanExecute(null)) vm.OpenDetailsCommand.Execute(null); } }
