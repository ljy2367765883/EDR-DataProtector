using System;
using System.Runtime.InteropServices;
using System.Text;

namespace DataProtectorWebBridge.Native
{
    internal static class DataProtectorPolicyNative
    {
        private const string DllName = "DataProtectorPolicyApi.dll";

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyCheckConnection();

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyAddProcessNameRuleEx(string processName, string extension);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyRemoveProcessNameRuleEx(string processName, string extension);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyAddProcessDirectoryRuleEx(string directoryPath, string extension);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyRemoveProcessDirectoryRuleEx(string directoryPath, string extension);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyAddExcludedDirectoryRuleEx(string directoryPath, string extension);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyRemoveExcludedDirectoryRuleEx(string directoryPath, string extension);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyClearProcessRules();

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryProcessRules(
            [Out] NativePolicyRule[] rules,
            uint ruleCapacity,
            out uint ruleCount,
            IntPtr stringBuffer,
            uint stringBufferChars,
            out uint stringBufferCharsRequired);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyAddNetworkRule(ref NativeNetworkRule rule);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyRemoveNetworkRule(uint ruleId);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyClearNetworkRules();

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryNetworkRules(
            [Out] NativeNetworkRule[] rules,
            uint ruleCapacity,
            out uint ruleCount,
            IntPtr stringBuffer,
            uint stringBufferChars,
            out uint stringBufferCharsRequired);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQuerySmtpEvents(
            [Out] NativeSmtpEvent[] events,
            uint eventCapacity,
            out uint eventCount,
            IntPtr stringBuffer,
            uint stringBufferChars,
            out uint stringBufferCharsRequired);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryNetworkConnectionEvents(
            [Out] NativeNetworkConnectionEvent[] events,
            uint eventCapacity,
            out uint eventCount,
            IntPtr stringBuffer,
            uint stringBufferChars,
            out uint stringBufferCharsRequired);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyAddWebShellRule(string directoryPath);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyRemoveWebShellRule(string directoryPath);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyClearWebShellRules();

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryWebShellRules(
            [Out] NativeWebShellRule[] rules,
            uint ruleCapacity,
            out uint ruleCount,
            IntPtr stringBuffer,
            uint stringBufferChars,
            out uint stringBufferCharsRequired);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryWebShellEvents(
            [Out] NativeWebShellEvent[] events,
            uint eventCapacity,
            out uint eventCount,
            IntPtr stringBuffer,
            uint stringBufferChars,
            out uint stringBufferCharsRequired);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryHashProtectEvents(
            [Out] NativeHashProtectEvent[] events,
            uint eventCapacity,
            out uint eventCount,
            IntPtr stringBuffer,
            uint stringBufferChars,
            out uint stringBufferCharsRequired);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicySetHashProtectPolicy(ref NativeHashProtectPolicy policy);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryHashProtectPolicy(out NativeHashProtectPolicy policy);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryLateralDefenseEvents(
            [Out] NativeLateralDefenseEvent[] events,
            uint eventCapacity,
            out uint eventCount,
            IntPtr stringBuffer,
            uint stringBufferChars,
            out uint stringBufferCharsRequired);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicySetLateralDefensePolicy(ref NativeLateralDefensePolicy policy);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryLateralDefensePolicy(out NativeLateralDefensePolicy policy);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryUserHookDefenseEvents(
            [Out] NativeUserHookDefenseEvent[] events,
            uint eventCapacity,
            out uint eventCount,
            IntPtr stringBuffer,
            uint stringBufferChars,
            out uint stringBufferCharsRequired);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicySetUserHookDefensePolicy(ref NativeUserHookDefensePolicy policy);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryUserHookDefensePolicy(out NativeUserHookDefensePolicy policy);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyConvertDosPathToNtPath(
            string dosPath,
            StringBuilder ntPath,
            uint ntPathChars);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyAddDeviceRule(ref NativeDeviceRule rule);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyRemoveDeviceRule(string deviceId);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyClearDeviceRules();

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryDeviceRules(
            [Out] NativeDeviceRule[] rules,
            uint ruleCapacity,
            out uint ruleCount,
            IntPtr stringBuffer,
            uint stringBufferChars,
            out uint stringBufferCharsRequired);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyWriteUsbMetadata(
            string physicalDrivePath,
            ulong requestedOffsetBytes,
            [In] byte[] metadata,
            out NativeUsbMetadataWriteResult result);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyInitializeUsbLayout(
            string physicalDrivePath,
            string preferredDriveRoot,
            ulong publicPartitionOffsetBytes,
            ulong publicPartitionBytes,
            StringBuilder driveRoot,
            uint driveRootChars,
            out NativeUsbLayoutResult result);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyGetLastErrorMessage(StringBuilder buffer, uint bufferChars);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct NativePolicyRule
        {
            public uint RuleType;
            public IntPtr Value;
            public IntPtr Extension;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct NativeNetworkRule
        {
            public uint RuleId;
            public uint Kind;
            public uint Action;
            public uint Protocol;
            public uint Direction;
            public uint LocalAddress;
            public uint LocalAddressMask;
            public uint RemoteAddress;
            public uint RemoteAddressMask;
            public ushort LocalPort;
            public ushort RemotePort;
            public IntPtr Domain;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct NativeSmtpEvent
        {
            public ulong Sequence;
            public ulong ProcessId;
            public uint LocalAddress;
            public uint RemoteAddress;
            public ushort LocalPort;
            public ushort RemotePort;
            public IntPtr From;
            public IntPtr To;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct NativeNetworkConnectionEvent
        {
            public ulong Sequence;
            public ulong ProcessId;
            public uint Direction;
            public uint Protocol;
            public uint LocalAddress;
            public uint RemoteAddress;
            public uint Flags;
            public ushort LocalPort;
            public ushort RemotePort;
            public IntPtr ProcessPath;
            public IntPtr Domain;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct NativeWebShellRule
        {
            public IntPtr Directory;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct NativeDeviceRule
        {
            public IntPtr DeviceId;
            public uint AllowInsert;
            public uint AllowWrite;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct NativeWebShellEvent
        {
            public ulong Sequence;
            public ulong ProcessId;
            public uint Severity;
            public uint Operation;
            public uint FileSize;
            public uint SampleLength;
            public IntPtr Path;
            public IntPtr Extension;

            public SampleBuffer Sample;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct NativeHashProtectEvent
        {
            public ulong Sequence;
            public ulong ProcessId;
            public uint Operation;
            public uint Status;
            public uint DesiredAccess;
            public IntPtr Target;
            public IntPtr ProcessImage;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct NativeHashProtectPolicy
        {
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct NativeLateralDefenseEvent
        {
            public ulong Sequence;
            public ulong ProcessId;
            public uint Operation;
            public uint Status;
            public uint DesiredAccess;
            public uint Flags;
            public IntPtr Target;
            public IntPtr ProcessImage;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct NativeLateralDefensePolicy
        {
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct NativeUserHookDefenseEvent
        {
            public ulong Sequence;
            public ulong ProcessId;
            public ulong ParentProcessId;
            public uint Operation;
            public uint Status;
            public uint Flags;
            public IntPtr Target;
            public IntPtr ProcessImage;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct NativeUserHookDefensePolicy
        {
            public uint Flags;
            public IntPtr ExcludedProcessNames;
            public IntPtr ExcludedProcessDirectories;
            public IntPtr ExcludedProcessPaths;
            public IntPtr TrustedSignerSubjects;
            public IntPtr RuntimeDllPath;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct NativeUsbMetadataWriteResult
        {
            public uint Status;
            public uint PartitionCount;
            public ulong OffsetBytes;
            public ulong DiskSizeBytes;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct NativeUsbLayoutResult
        {
            public uint Status;
            public uint DiskNumber;
            public ulong DiskSizeBytes;
            public ulong PublicPartitionOffsetBytes;
            public ulong PublicPartitionBytes;
        }

        [StructLayout(LayoutKind.Sequential, Size = 100)]
        internal unsafe struct SampleBuffer
        {
            public fixed byte Bytes[100];
        }
    }
}
