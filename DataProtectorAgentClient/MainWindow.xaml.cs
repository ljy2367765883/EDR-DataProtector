using DataProtectorAgentClient.Infrastructure;
using Wpf.Ui.Controls;

namespace DataProtectorAgentClient
{
    public partial class MainWindow : FluentWindow
    {
        public MainWindow()
        {
            InitializeComponent();
            SourceInitialized += delegate
            {
                WindowsAcrylicFallback.TryApply(this);
            };
        }
    }
}
