using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace DataProtectorAgentClient.Infrastructure
{
    public sealed class ResourceBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            string key = value as string;
            if (string.IsNullOrWhiteSpace(key))
            {
                return DependencyProperty.UnsetValue;
            }

            return Application.Current.TryFindResource(key);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException();
        }
    }
}
