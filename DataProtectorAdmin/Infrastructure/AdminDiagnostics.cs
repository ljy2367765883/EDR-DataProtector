using System;
using System.IO;
using System.Text;

namespace DataProtectorAdmin.Infrastructure
{
    internal static class AdminDiagnostics
    {
        private static readonly object SyncRoot = new object();

        public static string LogPath
        {
            get
            {
                string directory = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "DataProtector");

                return Path.Combine(directory, "Admin.log");
            }
        }

        public static void Log(string message)
        {
            Write(message);
        }

        public static void Log(Exception exception)
        {
            Write(exception == null ? "Unknown exception." : exception.ToString());
        }

        private static void Write(string message)
        {
            try
            {
                string directory = Path.GetDirectoryName(LogPath);
                if (!string.IsNullOrEmpty(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                string entry = string.Format(
                    "[{0:yyyy-MM-dd HH:mm:ss.fff}] {1}{2}",
                    DateTime.Now,
                    message,
                    Environment.NewLine);

                lock (SyncRoot)
                {
                    File.AppendAllText(LogPath, entry, Encoding.UTF8);
                }
            }
            catch
            {
                // Diagnostics must never take down the management UI.
            }
        }
    }
}
