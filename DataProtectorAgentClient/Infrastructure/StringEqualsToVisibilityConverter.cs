using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace DataProtectorAgentClient.Infrastructure
{
    public sealed class StringEqualsToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            string left = value == null ? string.Empty : value.ToString();
            string right = parameter == null ? string.Empty : parameter.ToString();
            return string.Equals(left, right, StringComparison.OrdinalIgnoreCase)
                ? Visibility.Visible
                : Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException();
        }
    }
}
