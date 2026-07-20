using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace TikTokProxyHunter.Desktop.Converters;

public sealed class PageVisibilityConverter : IValueConverter
{
    public int Page { get; set; }
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value is int current && current == Page ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}
