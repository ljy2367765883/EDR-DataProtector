using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace DataProtectorAgentClient.Infrastructure
{
    internal static class WindowsAcrylicFallback
    {
        private const int WcaAccentPolicy = 19;
        private const int AccentEnableGradient = 1;
        private const int AccentEnableBlurBehind = 3;
        private const int AccentEnableAcrylicBlurBehind = 4;
        private const int Windows10AcrylicBuild = 17134;
        private const int Windows11Build = 22000;
        private const int AcrylicTint = unchecked((int)0xD03D1424);
        private const int MoveTint = unchecked((int)0xF03D1424);

        public static void TryApply(Window window)
        {
            if (window == null)
            {
                return;
            }

            WindowsVersion version;
            if (!TryGetWindowsVersion(out version))
            {
                return;
            }

            if (version.Major != 10 || version.Build >= Windows11Build)
            {
                return;
            }

            IntPtr hwnd = new WindowInteropHelper(window).Handle;
            if (hwnd == IntPtr.Zero)
            {
                return;
            }

            ApplyAcrylic(hwnd);
        }

        public static void TrySuspendForMove(Window window)
        {
            if (window == null || !IsWindows10Before11())
            {
                return;
            }

            IntPtr hwnd = new WindowInteropHelper(window).Handle;
            if (hwnd != IntPtr.Zero)
            {
                ApplyAccent(hwnd, AccentEnableGradient, MoveTint);
            }
        }

        public static void TryResumeAfterMove(Window window)
        {
            if (window == null || !IsWindows10Before11())
            {
                return;
            }

            IntPtr hwnd = new WindowInteropHelper(window).Handle;
            if (hwnd != IntPtr.Zero)
            {
                ApplyAcrylic(hwnd);
            }
        }

        private static void ApplyAcrylic(IntPtr hwnd)
        {
            WindowsVersion version;
            if (!TryGetWindowsVersion(out version))
            {
                return;
            }

            int accentState = version.Build >= Windows10AcrylicBuild
                ? AccentEnableAcrylicBlurBehind
                : AccentEnableBlurBehind;

            ApplyAccent(hwnd, accentState, AcrylicTint);
        }

        private static void ApplyAccent(IntPtr hwnd, int accentState, int gradientColor)
        {
            AccentPolicy accent = new AccentPolicy
            {
                AccentState = accentState,
                AccentFlags = 2,
                GradientColor = gradientColor,
                AnimationId = 0
            };

            int accentSize = Marshal.SizeOf(typeof(AccentPolicy));
            IntPtr accentPtr = Marshal.AllocHGlobal(accentSize);

            try
            {
                Marshal.StructureToPtr(accent, accentPtr, false);

                WindowCompositionAttributeData data = new WindowCompositionAttributeData
                {
                    Attribute = WcaAccentPolicy,
                    Data = accentPtr,
                    SizeOfData = accentSize
                };

                SetWindowCompositionAttribute(hwnd, ref data);
            }
            finally
            {
                Marshal.FreeHGlobal(accentPtr);
            }
        }

        public static bool IsWindows10Before11()
        {
            WindowsVersion version;
            return TryGetWindowsVersion(out version) &&
                   version.Major == 10 &&
                   version.Build < Windows11Build;
        }

        private static bool TryGetWindowsVersion(out WindowsVersion version)
        {
            version = default(WindowsVersion);

            RtlOsVersionInfoEx info = new RtlOsVersionInfoEx
            {
                OSVersionInfoSize = Marshal.SizeOf(typeof(RtlOsVersionInfoEx))
            };

            if (RtlGetVersion(ref info) != 0)
            {
                return false;
            }

            version = new WindowsVersion(info.MajorVersion, info.BuildNumber);
            return true;
        }

        [DllImport("user32.dll")]
        private static extern int SetWindowCompositionAttribute(
            IntPtr hwnd,
            ref WindowCompositionAttributeData data);

        [DllImport("ntdll.dll")]
        private static extern int RtlGetVersion(ref RtlOsVersionInfoEx versionInformation);

        [StructLayout(LayoutKind.Sequential)]
        private struct AccentPolicy
        {
            public int AccentState;
            public int AccentFlags;
            public int GradientColor;
            public int AnimationId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WindowCompositionAttributeData
        {
            public int Attribute;
            public IntPtr Data;
            public int SizeOfData;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct RtlOsVersionInfoEx
        {
            public int OSVersionInfoSize;
            public int MajorVersion;
            public int MinorVersion;
            public int BuildNumber;
            public int PlatformId;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string CsdVersion;

            public ushort ServicePackMajor;
            public ushort ServicePackMinor;
            public ushort SuiteMask;
            public byte ProductType;
            public byte Reserved;
        }

        private struct WindowsVersion
        {
            public WindowsVersion(int major, int build)
            {
                Major = major;
                Build = build;
            }

            public int Major { get; }

            public int Build { get; }
        }
    }
}
