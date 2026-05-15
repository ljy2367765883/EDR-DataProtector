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
    }
}
