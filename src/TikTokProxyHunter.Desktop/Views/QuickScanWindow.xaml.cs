using System.Windows;

namespace TikTokProxyHunter.Desktop.Views;

public partial class QuickScanWindow : Window
{
    public bool AdvancedRequested { get; private set; }
    public QuickScanWindow() => InitializeComponent();
    private void Start_Click(object sender, RoutedEventArgs e) { DialogResult = true; Close(); }
    private void Advanced_Click(object sender, RoutedEventArgs e) { AdvancedRequested = true; DialogResult = false; Close(); }
}
