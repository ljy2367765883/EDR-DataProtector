using System;
using System.Runtime.InteropServices;
using System.Text;

namespace DataProtectorAgentClient.Native
{
    internal static class DataProtectorPolicyNative
    {
        private const string DllName = "DataProtectorPolicyApi.dll";

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyCheckConnection();

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryProcessRules(
            [Out] NativePolicyRule[] rules,
            uint ruleCapacity,
            out uint ruleCount,
            IntPtr stringBuffer,
            uint stringBufferChars,
            out uint stringBufferCharsRequired);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryNetworkRules(
            [Out] NativeNetworkRule[] rules,
            uint ruleCapacity,
            out uint ruleCount,
            IntPtr stringBuffer,
            uint stringBufferChars,
            out uint stringBufferCharsRequired);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryWebShellRules(
            [Out] NativeWebShellRule[] rules,
            uint ruleCapacity,
            out uint ruleCount,
            IntPtr stringBuffer,
            uint stringBufferChars,
            out uint stringBufferCharsRequired);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryDeviceRules(
            [Out] NativeDeviceRule[] rules,
            uint ruleCapacity,
            out uint ruleCount,
            IntPtr stringBuffer,
            uint stringBufferChars,
            out uint stringBufferCharsRequired);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryHashProtectPolicy(out NativeHashProtectPolicy policy);

        [DllImport(DllName, CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern uint DpPolicyQueryLateralDefensePolicy(out NativeLateralDefensePolicy policy);

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

        [StructLayout(LayoutKind.Sequential)]
        internal struct NativeHashProtectPolicy
        {
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct NativeLateralDefensePolicy
        {
            public uint Flags;
        }
    }
}
