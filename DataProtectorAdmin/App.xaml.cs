using System;
using System.Drawing;
using System.Threading.Tasks;
using Forms = System.Windows.Forms;
using System.Windows;
using System.Windows.Threading;
using DataProtectorAdmin.Infrastructure;
using DataProtectorAdmin.Services;
using DataProtectorAdmin.ViewModels;

namespace DataProtectorAdmin
{
    public partial class App : Application
    {
        private Forms.NotifyIcon notifyIcon;
        private bool isExitRequested;

        protected override void OnStartup(StartupEventArgs e)
        {
            RegisterExceptionHandlers();
            AdminDiagnostics.Log("DataProtectorAdmin starting.");
            base.OnStartup(e);

            IPolicySettingsStore settingsStore = new PolicySettingsStore();
            IDataProtectorPolicyService policyService = new DataProtectorPolicyService(settingsStore);
            MainViewModel viewModel = new MainViewModel(policyService);

            MainWindow window = new MainWindow
            {
                DataContext = viewModel
            };

            MainWindow = window;
            InitializeTrayIcon(window);
            window.Show();
        }

        private static void RegisterExceptionHandlers()
        {
            Current.DispatcherUnhandledException += OnDispatcherUnhandledException;
            AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
            TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        }

        private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            AdminDiagnostics.Log(e.Exception);
            e.Handled = true;

            MessageBox.Show(
                "管理端操作失败，详细信息已写入：" + Environment.NewLine + AdminDiagnostics.LogPath,
                "DataProtector",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }

        private static void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            AdminDiagnostics.Log(e.ExceptionObject as Exception);
        }

        private static void OnUnobservedTaskException(object sender, UnobservedTaskExceptionEventArgs e)
        {
            AdminDiagnostics.Log(e.Exception);
            e.SetObserved();
        }

        protected override void OnExit(ExitEventArgs e)
        {
            AdminDiagnostics.Log("DataProtectorAdmin exiting.");

            if (notifyIcon != null)
            {
                notifyIcon.Visible = false;
                notifyIcon.Dispose();
                notifyIcon = null;
            }

            base.OnExit(e);
        }

        private void InitializeTrayIcon(Window window)
        {
            Forms.ContextMenuStrip menu = new Forms.ContextMenuStrip();
            Forms.ToolStripMenuItem showItem = new Forms.ToolStripMenuItem("打开 DataProtector");
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
                Text = "DataProtector Policy Control Center",
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
                notifyIcon.ShowBalloonTip(2500, "DataProtector", "管理工具仍在托盘运行。", Forms.ToolTipIcon.Info);
            };
        }

        private static Icon LoadTrayIcon()
        {
            Uri iconUri = new Uri("pack://application:,,,/Assets/AppIcon.ico", UriKind.Absolute);
            using (System.IO.Stream stream = Application.GetResourceStream(iconUri).Stream)
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
