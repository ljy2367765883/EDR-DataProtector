using System;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using DataProtectorAgentClient.Services;
using DataProtectorAgentClient.ViewModels;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;
using Forms = System.Windows.Forms;

namespace DataProtectorAgentClient
{
    public partial class App : Application
    {
        private Forms.NotifyIcon notifyIcon;
        private bool isExitRequested;

        protected override void OnStartup(StartupEventArgs e)
        {
            RegisterExceptionHandlers();
            base.OnStartup(e);
            ApplicationThemeManager.Apply(ApplicationTheme.Dark, WindowBackdropType.Acrylic, true);

            MainViewModel viewModel = new MainViewModel(new AgentClientSnapshotService());
            MainWindow window = new MainWindow
            {
                DataContext = viewModel
            };

            MainWindow = window;
            InitializeTrayIcon(window);
            window.Show();
            viewModel.RefreshAsync();
        }

        protected override void OnExit(ExitEventArgs e)
        {
            if (notifyIcon != null)
            {
                notifyIcon.Visible = false;
                notifyIcon.Dispose();
                notifyIcon = null;
            }

            base.OnExit(e);
        }

        private static void RegisterExceptionHandlers()
        {
            Current.DispatcherUnhandledException += OnDispatcherUnhandledException;
            AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
            TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        }

        private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            e.Handled = true;
            System.Windows.MessageBox.Show(
                "DataProtector Agent 客户端运行异常：" + Environment.NewLine + e.Exception.Message,
                "DataProtector Agent",
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Error);
        }

        private static void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
        }

        private static void OnUnobservedTaskException(object sender, UnobservedTaskExceptionEventArgs e)
        {
            e.SetObserved();
        }

        private void InitializeTrayIcon(Window window)
        {
            Forms.ContextMenuStrip menu = new Forms.ContextMenuStrip();
            Forms.ToolStripMenuItem showItem = new Forms.ToolStripMenuItem("打开 DataProtector Agent");
            Forms.ToolStripMenuItem exitItem = new Forms.ToolStripMenuItem("退出");

            showItem.Click += delegate { ShowMainWindow(window); };
            exitItem.Click += delegate
            {
                isExitRequested = true;
                Shutdown();
            };

            menu.Items.Add(showItem);
            menu.Items.Add(new Forms.ToolStripSeparator());
            menu.Items.Add(exitItem);

            notifyIcon = new Forms.NotifyIcon
            {
                Icon = LoadTrayIcon(),
                Text = "DataProtector Agent",
                ContextMenuStrip = menu,
                Visible = true
            };

            notifyIcon.DoubleClick += delegate { ShowMainWindow(window); };

            window.Closing += delegate(object sender, System.ComponentModel.CancelEventArgs args)
            {
                if (isExitRequested)
                {
                    return;
                }

                args.Cancel = true;
                window.Hide();
                notifyIcon.ShowBalloonTip(1800, "DataProtector Agent", "客户端已最小化到托盘。", Forms.ToolTipIcon.Info);
            };
        }

        private static Icon LoadTrayIcon()
        {
            Uri iconUri = new Uri("pack://application:,,,/AppIcon.ico", UriKind.Absolute);
            using (System.IO.Stream stream = GetResourceStream(iconUri).Stream)
            {
                return new Icon(stream);
            }
        }

        private static void ShowMainWindow(Window window)
        {
            if (window.WindowState == WindowState.Minimized)
            {
                window.WindowState = WindowState.Normal;
            }

            window.Show();
            window.Activate();
        }
    }
}
