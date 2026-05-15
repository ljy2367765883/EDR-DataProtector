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
        internal static extern uint DpPolicyGetLastErrorMessage(StringBuilder buffer, uint bufferChars);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct NativePolicyRule
        {
            public uint RuleType;
            public IntPtr Value;
            public IntPtr Extension;
        }
    }
}
