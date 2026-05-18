using DataProtectorAgentClient.Infrastructure;
using System;
using System.Windows;
using System.Windows.Interop;
using Wpf.Ui.Controls;

namespace DataProtectorAgentClient
{
    public partial class MainWindow : FluentWindow
    {
        private const int WmEnterSizeMove = 0x0231;
        private const int WmExitSizeMove = 0x0232;

        public MainWindow()
        {
            InitializeComponent();
            if (WindowsAcrylicFallback.IsWindows10Before11())
            {
                WindowBackdropType = WindowBackdropType.None;
            }

            SourceInitialized += delegate
            {
                WindowsAcrylicFallback.TryApply(this);
                HwndSource source = PresentationSource.FromVisual(this) as HwndSource;
                if (source != null)
                {
                    source.AddHook(WndProc);
                }
            };
        }

        private IntPtr WndProc(IntPtr hwnd, int message, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            if (message == WmEnterSizeMove)
            {
                WindowsAcrylicFallback.TrySuspendForMove(this);
            }
            else if (message == WmExitSizeMove)
            {
                WindowsAcrylicFallback.TryResumeAfterMove(this);
            }

            return IntPtr.Zero;
        }
    }
}
